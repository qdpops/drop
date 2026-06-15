package xyz.olcrtc.android

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap

/**
 * In-process TUN packet forwarder.
 *
 * Each TCP connection is represented by a single TcpConn from SYN to FIN.
 * Browser→SOCKS5 data goes through an unbounded Channel, which guarantees
 * FIFO ordering regardless of which IO thread processes each packet.
 * This prevents ERR_SSL_BAD_RECORD_MAC_ALERT caused by out-of-order writes.
 *
 * SYN flow:
 *   SYN arrives → TcpConn created, added to connections map, SYN+ACK sent immediately
 *   openSocksConn runs in background: connects SOCKS5, starts channel writer + socket reader
 *   Data that arrives before SOCKS5 is ready queues in conn.outgoing (Channel.UNLIMITED)
 *   Once SOCKS5 connects, writer drains the channel in order
 */
class TunPacketForwarder(
    private val vpnService: VpnService,
    private val tunFd: ParcelFileDescriptor,
    private val socksPort: Int,
    private val dnsServer: String,
    private val dnsProxyPort: Int,
    private val onLog: (String) -> Unit,
    private val scope: CoroutineScope
) {
    companion object {
        private const val TAG = "TunForwarder"
        private const val MTU = 1500
        private const val PROTO_TCP = 6
        private const val PROTO_UDP = 17
        private const val MSS = 1460
        // TCP MSS option: kind=2, len=4, value=1460 — sent only in SYN+ACK
        private val MSS_OPTION = byteArrayOf(0x02, 0x04, 0x05, 0xb4.toByte())
    }

    private val connections = ConcurrentHashMap<String, TcpConn>()
    // Single writer channel: all coroutines enqueue packets here; one dedicated
    // coroutine drains them in order. Avoids @Synchronized contention when many
    // connections write to TUN simultaneously.
    private val tunWriteQueue = Channel<ByteArray>(Channel.UNLIMITED)

    private inner class TcpConn(
        @Volatile var clientSeq: Int,   // next expected seq from browser
        @Volatile var serverSeq: Int,   // next seq we send to browser
        val srcIp: Int,
        val srcPort: Int,
        val dstIp: Int,
        val dstPort: Int
    ) {
        // All browser→SOCKS5 data goes through this channel (FIFO, preserves TCP order)
        val outgoing = Channel<ByteArray>(Channel.UNLIMITED)
        @Volatile var socket: Socket? = null
    }

    // ─── Entry point ─────────────────────────────────────────────────────────

    fun start() {
        val output = FileOutputStream(tunFd.fileDescriptor)

        // Dedicated writer: drains tunWriteQueue sequentially. Each write() to
        // a TUN fd must be exactly one IP packet — no interleaving allowed.
        scope.launch(Dispatchers.IO) {
            for (pkt in tunWriteQueue) {
                try { output.write(pkt) } catch (_: Exception) { break }
            }
        }

        scope.launch(Dispatchers.IO) {
            val input  = FileInputStream(tunFd.fileDescriptor)
            val buffer = ByteArray(MTU)
            onLog("TUN forwarder started (SOCKS5 → 127.0.0.1:$socksPort, DNS → $dnsServer)")

            while (isActive) {
                val len = try { input.read(buffer) } catch (_: Exception) { break }
                if (len <= 0) continue
                handlePacket(buffer.copyOf(len))
            }
            tunWriteQueue.close()
            onLog("TUN forwarder stopped")
        }
    }

    // ─── Packet dispatch ─────────────────────────────────────────────────────

    private fun handlePacket(pkt: ByteArray) {
        if (pkt.size < 20) return
        val version = (pkt[0].toInt() ushr 4) and 0xF
        if (version != 4) return

        val ihl   = (pkt[0].toInt() and 0xF) * 4
        val proto = pkt[9].toInt() and 0xFF
        val srcIp = readInt(pkt, 12)
        val dstIp = readInt(pkt, 16)
        if (pkt.size < ihl) return

        when (proto) {
            PROTO_TCP -> handleTcp(pkt, ihl, srcIp, dstIp)
            PROTO_UDP -> handleUdp(pkt, ihl, srcIp, dstIp)
        }
    }

    // ─── TCP ─────────────────────────────────────────────────────────────────

    private fun handleTcp(pkt: ByteArray, ipLen: Int, srcIp: Int, dstIp: Int) {
        if (pkt.size < ipLen + 20) return
        val srcPort = readU16(pkt, ipLen)
        val dstPort = readU16(pkt, ipLen + 2)
        val seq     = readInt(pkt, ipLen + 4)
        val dataOff = ((pkt[ipLen + 12].toInt() ushr 4) and 0xF) * 4
        val flags   = pkt[ipLen + 13].toInt() and 0xFF
        val payload = if (ipLen + dataOff < pkt.size) pkt.copyOfRange(ipLen + dataOff, pkt.size)
                      else byteArrayOf()

        val isSyn = flags and 0x02 != 0
        val isAck = flags and 0x10 != 0
        val isFin = flags and 0x01 != 0
        val isRst = flags and 0x04 != 0

        val key = connKey(srcIp, srcPort, dstIp, dstPort)

        when {
            isRst -> {
                val conn = connections.remove(key)
                conn?.outgoing?.close()
                conn?.socket?.closeSilently()
            }

            isSyn && !isAck -> {
                if (connections.containsKey(key)) return // deduplicate SYN retransmits

                val serverInitSeq = (Math.random() * 0x7FFFFFFF).toInt()
                val conn = TcpConn(
                    clientSeq = seq + 1,
                    serverSeq = serverInitSeq + 1,
                    srcIp = srcIp, srcPort = srcPort,
                    dstIp = dstIp, dstPort = dstPort
                )
                connections[key] = conn

                // Respond immediately so browser doesn't time out waiting for SYN+ACK.
                // MSS=1460 so the peer sends full-size segments instead of the 536-byte default.
                writeTun(buildTcp(dstIp, dstPort, srcIp, srcPort,
                    serverInitSeq, seq + 1, 0x12, options = MSS_OPTION))  // SYN+ACK

                scope.launch(Dispatchers.IO) {
                    openSocksConn(key, conn)
                }
            }

            isFin -> {
                val conn = connections.remove(key)
                if (conn != null) {
                    writeTun(buildTcp(dstIp, dstPort, srcIp, srcPort,
                        conn.serverSeq, seq + 1, 0x11))  // FIN+ACK
                    conn.outgoing.close()
                    conn.socket?.closeSilently()
                }
            }

            payload.isNotEmpty() -> {
                val conn = connections[key]
                when {
                    conn != null -> {
                        // ACK immediately; queue data into channel for ordered SOCKS5 delivery
                        conn.clientSeq += payload.size
                        writeTun(buildTcp(dstIp, dstPort, srcIp, srcPort,
                            conn.serverSeq, conn.clientSeq, 0x10))  // ACK
                        conn.outgoing.trySend(payload.copyOf())
                    }
                    else -> {
                        writeTun(buildTcp(dstIp, dstPort, srcIp, srcPort,
                            0, seq + payload.size, 0x04))  // RST — unknown connection
                    }
                }
            }
        }
    }

    // ─── SOCKS5 connect (background) ─────────────────────────────────────────

    private suspend fun openSocksConn(key: String, conn: TcpConn) {
        val dstIpStr = intToIp(conn.dstIp)
        try {
            val proxy  = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort))
            val socket = Socket(proxy)
            vpnService.protect(socket)
            socket.soTimeout = 10_000  // timeout for SOCKS5 handshake only
            socket.connect(InetSocketAddress(dstIpStr, conn.dstPort), 8_000)
            socket.soTimeout = 0       // no timeout on established connections
            conn.socket = socket

            // Writer: drains outgoing channel → socket in FIFO order.
            // Any data that queued during SOCKS5 connect is sent first, then live data.
            val writerJob = scope.launch(Dispatchers.IO) {
                try {
                    for (data in conn.outgoing) {
                        socket.getOutputStream().apply { write(data); flush() }
                    }
                } catch (_: Exception) {
                    conn.outgoing.close()
                }
            }

            val buf = ByteArray(16384) // 16 KB: fits one TLS record per read
            try {
                while (true) {
                    val n = socket.getInputStream().read(buf)
                    if (n <= 0) break
                    // Chunk into MSS-sized segments so we never exceed IP MTU.
                    var off = 0
                    while (off < n) {
                        val end = minOf(off + MSS, n)
                        writeTun(buildTcp(conn.dstIp, conn.dstPort,
                            conn.srcIp, conn.srcPort,
                            conn.serverSeq, conn.clientSeq, 0x18,
                            buf.copyOfRange(off, end)))
                        conn.serverSeq += end - off
                        off = end
                    }
                }
            } finally {
                writerJob.cancel()
                conn.outgoing.close()
                if (connections.remove(key) != null) {
                    // Send FIN+ACK only if we're the one closing (not a browser-initiated FIN)
                    writeTun(buildTcp(conn.dstIp, conn.dstPort,
                        conn.srcIp, conn.srcPort, conn.serverSeq, conn.clientSeq, 0x11))
                }
                socket.closeSilently()
            }

        } catch (e: CancellationException) {
            connections.remove(key)
            conn.outgoing.close()
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "SOCKS5 connect failed ($dstIpStr:${conn.dstPort}): ${e.message}")
            connections.remove(key)
            conn.outgoing.close()
            writeTun(buildTcp(conn.dstIp, conn.dstPort,
                conn.srcIp, conn.srcPort, 0, conn.clientSeq, 0x04))  // RST
        }
    }

    // ─── UDP / DNS ────────────────────────────────────────────────────────────

    private fun handleUdp(pkt: ByteArray, ipLen: Int, srcIp: Int, dstIp: Int) {
        if (pkt.size < ipLen + 8) return
        val srcPort = readU16(pkt, ipLen)
        val dstPort = readU16(pkt, ipLen + 2)
        val payload = pkt.copyOfRange(ipLen + 8, pkt.size)

        when (dstPort) {
            53 -> scope.launch(Dispatchers.IO) {
                forwardDns(payload, srcIp, srcPort)
            }
            else -> {
                // ICMP Port Unreachable: tells Chrome/Firefox to fall back from QUIC to TCP/HTTP2
                writeTun(buildIcmpUnreachable(pkt, ipLen, srcIp, dstIp))
            }
        }
    }

    private suspend fun forwardDns(query: ByteArray, srcIp: Int, srcPort: Int) {
        try {
            // Send to LocalDnsProxy (127.0.0.1:dnsProxyPort) — loopback bypasses VPN
            // naturally so protect() is not needed. Raw UDP to external DNS (8.8.8.8:53)
            // fails on some operators (e.g. Megafon) after TUN is established.
            // use{} guarantees close() even on SocketTimeoutException, preventing FD leak.
            DatagramSocket().use { sock ->
                sock.soTimeout = 3_000
                sock.send(DatagramPacket(query, query.size,
                    InetAddress.getByName("127.0.0.1"), dnsProxyPort))
                val resp = ByteArray(512)
                val dp   = DatagramPacket(resp, resp.size)
                sock.receive(dp)
                // Response must appear to come from dnsServer (e.g. 8.8.8.8) — that is
                // what the app sent its query to, so the reply source must match.
                writeTun(buildUdp(ipToInt(dnsServer), 53, srcIp, srcPort, resp.copyOf(dp.length)))
            }
        } catch (e: Exception) {
            Log.w(TAG, "DNS failed: ${e.message}")
        }
    }

    // ─── Packet builders ──────────────────────────────────────────────────────

    private fun buildTcp(
        srcIp: Int, srcPort: Int,
        dstIp: Int, dstPort: Int,
        seq: Int, ack: Int,
        flags: Int,
        data: ByteArray = byteArrayOf(),
        options: ByteArray = byteArrayOf()
    ): ByteArray {
        val tcpHdrLen = 20 + options.size          // options must be 4-byte aligned
        val tcpLen    = tcpHdrLen + data.size
        val totalLen  = 20 + tcpLen
        val buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN)

        buf.put(0x45.toByte()); buf.put(0)
        buf.putShort(totalLen.toShort())
        buf.putShort(0); buf.putShort(0x4000.toShort())
        buf.put(64); buf.put(PROTO_TCP.toByte())
        buf.putShort(0)
        buf.putInt(srcIp); buf.putInt(dstIp)
        buf.putShort(10, checksum(buf.array(), 0, 20))

        val t = 20
        buf.putShort(srcPort.toShort()); buf.putShort(dstPort.toShort())
        buf.putInt(seq); buf.putInt(ack)
        buf.put(((tcpHdrLen / 4) shl 4).toByte()); buf.put(flags.toByte())
        buf.putShort(0xFFFF.toShort())
        buf.putShort(0)
        buf.putShort(0)
        if (options.isNotEmpty()) buf.put(options)
        if (data.isNotEmpty()) buf.put(data)

        buf.putShort(t + 16, tcpChecksum(srcIp, dstIp, buf.array(), t, tcpLen))
        return buf.array()
    }

    private fun buildIcmpUnreachable(origPkt: ByteArray, origIpLen: Int, srcIp: Int, dstIp: Int): ByteArray {
        val icmpDataLen = minOf(origIpLen + 8, origPkt.size)
        val icmpData    = origPkt.copyOf(icmpDataLen)
        val icmpLen     = 8 + icmpDataLen
        val totalLen    = 20 + icmpLen

        val buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN)
        buf.put(0x45.toByte()); buf.put(0)
        buf.putShort(totalLen.toShort())
        buf.putShort(0); buf.putShort(0x4000.toShort())
        buf.put(64); buf.put(1)
        buf.putShort(0)
        buf.putInt(dstIp)
        buf.putInt(srcIp)
        buf.putShort(10, checksum(buf.array(), 0, 20))

        val icmpOffset = 20
        buf.put(3); buf.put(3)
        buf.putShort(0)
        buf.putInt(0)
        buf.put(icmpData)
        buf.putShort(icmpOffset + 2, checksum(buf.array(), icmpOffset, icmpLen))
        return buf.array()
    }

    private fun buildUdp(
        srcIp: Int, srcPort: Int,
        dstIp: Int, dstPort: Int,
        data: ByteArray
    ): ByteArray {
        val udpLen   = 8 + data.size
        val totalLen = 20 + udpLen
        val buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN)

        buf.put(0x45.toByte()); buf.put(0)
        buf.putShort(totalLen.toShort())
        buf.putShort(0); buf.putShort(0x4000.toShort())
        buf.put(64); buf.put(PROTO_UDP.toByte())
        buf.putShort(0)
        buf.putInt(srcIp); buf.putInt(dstIp)
        buf.putShort(10, checksum(buf.array(), 0, 20))
        buf.putShort(srcPort.toShort()); buf.putShort(dstPort.toShort())
        buf.putShort(udpLen.toShort()); buf.putShort(0)
        buf.put(data)
        return buf.array()
    }

    // ─── Checksums ────────────────────────────────────────────────────────────

    private fun checksum(data: ByteArray, offset: Int, length: Int): Short {
        var sum = 0L
        var i = offset
        while (i < offset + length - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (length % 2 != 0) sum += (data[offset + length - 1].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toShort()
    }

    private fun tcpChecksum(srcIp: Int, dstIp: Int, pkt: ByteArray, tcpOffset: Int, tcpLen: Int): Short {
        val pseudo = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
            .putInt(srcIp).putInt(dstIp).put(0).put(PROTO_TCP.toByte())
            .putShort(tcpLen.toShort()).array()
        val combined = pseudo + pkt.copyOfRange(tcpOffset, tcpOffset + tcpLen)
        return checksum(combined, 0, combined.size)
    }

    // ─── I/O ─────────────────────────────────────────────────────────────────

    private fun writeTun(pkt: ByteArray) {
        tunWriteQueue.trySend(pkt)
    }

    private fun Socket.closeSilently() = try { close() } catch (_: Exception) {}

    // ─── Byte helpers ─────────────────────────────────────────────────────────

    private fun readInt(b: ByteArray, o: Int) =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o+1].toInt() and 0xFF) shl 16) or
        ((b[o+2].toInt() and 0xFF) shl 8)  or  (b[o+3].toInt() and 0xFF)

    private fun readU16(b: ByteArray, o: Int) =
        ((b[o].toInt() and 0xFF) shl 8) or (b[o+1].toInt() and 0xFF)

    private fun intToIp(ip: Int) =
        "${(ip ushr 24) and 0xFF}.${(ip ushr 16) and 0xFF}.${(ip ushr 8) and 0xFF}.${ip and 0xFF}"

    private fun ipToInt(ip: String): Int {
        val p = ip.split(".")
        return (p[0].toInt() shl 24) or (p[1].toInt() shl 16) or (p[2].toInt() shl 8) or p[3].toInt()
    }

    private fun connKey(srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int) =
        "$srcIp:$srcPort→$dstIp:$dstPort"
}
