package xyz.olcrtc.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import kotlinx.coroutines.*
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.URI

/**
 * VPN mode: drop-client (SOCKS5) + in-process TunPacketForwarder (TUN → SOCKS5)
 *
 * Architecture:
 *   All apps → TUN fd (VpnService)
 *              → TunPacketForwarder [SAME PROCESS]
 *              → SOCKS5 127.0.0.1:$socksPort
 *              → drop-client subprocess
 *              → DROP tunnel (HTTPS/CDN) → Internet
 *
 * Why in-process (not tun2socks subprocess):
 *   Android SELinux blocks ioctl(TUNGETIFF) in child processes even when
 *   fd is properly inherited → "create tun: permission denied".
 *   In-process forwarder runs in VpnService's SELinux context → works.
 */
class OlcVpnService : VpnService() {

    companion object {
        private const val TAG = "OlcVpnService"
        const val CHANNEL_ID      = "drop_vpn"
        const val NOTIFICATION_ID = 2

        const val ACTION_START_VPN = "xyz.drop.START_VPN"
        const val ACTION_STOP_VPN  = "xyz.drop.STOP_VPN"

        const val EXTRA_URL  = "server_url"
        const val EXTRA_PUB  = "pub_key"
        const val EXTRA_PSK  = "psk"
        const val EXTRA_PORT = "socks_port"
        const val EXTRA_DNS  = "dns"

        const val BROADCAST_VPN_STATUS = "xyz.drop.VPN_STATUS"
        const val STATUS_VPN_UP        = "VPN_UP"
        const val STATUS_VPN_DOWN      = "VPN_DOWN"
        const val STATUS_VPN_ERROR     = "VPN_ERROR"
        const val STATUS_VPN_STARTING  = "VPN_STARTING"

        private const val VPN_ADDRESS    = "10.233.233.1"
        private const val VPN_ROUTE      = "0.0.0.0"
        private const val VPN_PREFIX_LEN = 0
        private const val MTU            = 1500
        private const val RECONNECT_DELAY_MS = 3000L
    }

    private val serviceScope = CoroutineScope(
        SupervisorJob() +
        Dispatchers.IO +
        CoroutineExceptionHandler { _, e ->
            if (e !is CancellationException) {
                Log.e(TAG, "Unhandled coroutine exception: ${e.message}", e)
            }
        }
    )

    @Volatile private var tunFd:       ParcelFileDescriptor? = null
    @Volatile private var dropProcess: Process? = null
    @Volatile private var isRunning = false

    private var serverUrl = ""
    private var pubKey    = ""
    private var psk       = ""
    private var socksPort = 8808
    private var dnsServer = ""

    // Network change: just kill the current session — the reconnect loop restarts it.
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: android.net.Network) {
            if (isRunning) {
                broadcastLog("Смена сети — перезапуск VPN")
                Log.i(TAG, "Network changed — killing session for reconnect")
                dropProcess?.destroy()
                tunFd?.close()
            }
        }
    }

    // ─── Lifecycle ────────────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val req = android.net.NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        try { cm.registerNetworkCallback(req, networkCallback) } catch (_: Exception) {}
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP_VPN -> {
                stopVpn()
                stopForeground(STOP_FOREGROUND_REMOVE)
                getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START_VPN -> {
                serverUrl = intent.getStringExtra(EXTRA_URL)  ?: ""
                pubKey    = intent.getStringExtra(EXTRA_PUB)  ?: ""
                psk       = intent.getStringExtra(EXTRA_PSK)  ?: ""
                socksPort = intent.getIntExtra(EXTRA_PORT, 8808)
                dnsServer = intent.getStringExtra(EXTRA_DNS)  ?: ""
            }
        }
        startForeground(NOTIFICATION_ID, buildNotification(STATUS_VPN_STARTING))
        serviceScope.launch { startVpn() }
        return START_STICKY
    }

    override fun onRevoke() {
        unregisterNetworkCallback()
        stopVpn()
        stopForeground(STOP_FOREGROUND_REMOVE)
        getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        super.onRevoke()
    }

    override fun onDestroy() {
        unregisterNetworkCallback()
        stopVpn()
        stopForeground(STOP_FOREGROUND_REMOVE)
        getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        serviceScope.cancel()
        super.onDestroy()
    }

    // ─── VPN lifecycle ────────────────────────────────────────────────────────

    private suspend fun startVpn() {
        isRunning = true

        val dropBinary = try {
            BinaryManager.getBinary(this)
        } catch (e: Exception) {
            broadcastStatus(STATUS_VPN_ERROR, "drop binary not found: ${e.message}")
            isRunning = false
            return
        }

        // Reconnect loop: runs while isRunning, restarts after each session ends.
        while (isRunning) {
            broadcastStatus(STATUS_VPN_STARTING)
            runVpnSession(dropBinary.absolutePath)
            if (!isRunning) break
            broadcastLog("Переподключение через ${RECONNECT_DELAY_MS / 1000} с...")
            delay(RECONNECT_DELAY_MS)
        }
    }

    /**
     * Runs one VPN session: starts drop-client, creates TUN, runs forwarder.
     * Suspends until the session ends (drop process exits or tunFd is closed).
     * Cleans up before returning so the outer loop can restart cleanly.
     */
    private suspend fun runVpnSession(binaryPath: String) {
        // publicDns: for addDnsServer() and TunPacketForwarder DNS relay.
        // Must be publicly routable. A carrier-local address (e.g., 192.168.1.1 from
        // a home WiFi router saved on a previous session) will time out after a network
        // switch, so fall back to 8.8.8.8 in that case.
        val savedDns = dnsServer
        val publicDns = if (savedDns.isNotBlank() && isPublicIp(savedDns)) savedDns else "8.8.8.8"

        // operatorDns: for libdrop.so to resolve the CDN hostname before VPN is up.
        // Probe candidates in order — use the first DNS that successfully resolves
        // the server hostname. Falls back to 8.8.8.8 if none respond.
        val hostname = runCatching { URI(serverUrl).host }.getOrNull() ?: ""
        val rawOperatorDns = detectOperatorDns()
        val dnsCandidates = buildList {
            // Operator DNS always first — even RFC-1918 addresses work because
            // the app is excluded from VPN via addDisallowedApplication, so
            // libdrop.so sockets reach the carrier's private DNS directly.
            if (rawOperatorDns.isNotEmpty()) add(rawOperatorDns)
            add("77.88.8.8")   // Yandex DNS
            add("8.8.8.8")     // Google DNS (libdrop.so falls back to DoH if UDP blocked)
        }.distinct()
        val operatorDns = if (hostname.isNotEmpty()) {
            selectWorkingDns(hostname, dnsCandidates)
        } else {
            dnsCandidates.first()
        }
        broadcastLog("DNS: tunnel=$publicDns resolver=$operatorDns")

        startDropProcess(binaryPath, operatorDns)
        broadcastLog("Waiting for SOCKS5 server...")
        delay(2000)

        val fd = buildTunInterface(publicDns)
        if (fd == null) {
            broadcastStatus(STATUS_VPN_ERROR, "Failed to create TUN interface")
            dropProcess?.destroy(); dropProcess = null
            return
        }
        tunFd = fd
        broadcastLog("TUN fd=${fd.fd} created")

        TunPacketForwarder(
            vpnService = this,
            tunFd      = fd,
            socksPort  = socksPort,
            dnsServer  = publicDns,
            onLog      = { line -> broadcastLog(line) },
            scope      = serviceScope
        ).start()

        broadcastStatus(STATUS_VPN_UP)
        updateNotification(STATUS_VPN_UP)
        Log.i(TAG, "VPN UP — SOCKS5 127.0.0.1:$socksPort DNS $publicDns resolver $operatorDns")

        // Suspend here until drop-client exits (network change, error, or user stop).
        withContext(Dispatchers.IO) { dropProcess?.waitFor() }

        // Session ended — clean up before the loop decides whether to restart.
        dropProcess?.destroy(); dropProcess = null
        tunFd?.close();         tunFd       = null
        broadcastStatus(STATUS_VPN_DOWN)
        updateNotification(STATUS_VPN_DOWN)
        broadcastLog("VPN сессия завершена")
    }

    // ─── Stop (user-initiated) ────────────────────────────────────────────────

    private fun stopVpn() {
        isRunning = false
        dropProcess?.destroy(); dropProcess = null
        tunFd?.close();         tunFd       = null
        // Cancel all children so the reconnect loop and forwarder stop immediately.
        serviceScope.coroutineContext[Job]?.cancelChildren()
        broadcastStatus(STATUS_VPN_DOWN)
        updateNotification(STATUS_VPN_DOWN)
    }

    private fun unregisterNetworkCallback() {
        try {
            (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                .unregisterNetworkCallback(networkCallback)
        } catch (_: Exception) {}
    }

    // ─── TUN interface ────────────────────────────────────────────────────────

    private fun buildTunInterface(dns: String): ParcelFileDescriptor? {
        return try {
            Builder()
                .setSession("DROP VPN")
                .setMtu(MTU)
                .addAddress(VPN_ADDRESS, 30)
                .addRoute(VPN_ROUTE, VPN_PREFIX_LEN)
                .addDnsServer(dns)
                .setBlocking(true)
                .addDisallowedApplication(packageName)
                .establish()
        } catch (e: Exception) {
            Log.e(TAG, "buildTunInterface: ${e.message}")
            null
        }
    }

    // ─── drop-client process ──────────────────────────────────────────────────

    private fun startDropProcess(binaryPath: String, dns: String) {
        val cmd = BinaryManager.buildCommand(binaryPath, serverUrl, pubKey, psk, socksPort, dns)
        Log.i(TAG, "Starting drop-client: ${cmd.joinToString(" ")}")
        try {
            dropProcess = ProcessBuilder(cmd)
                .redirectErrorStream(true)
                .directory(filesDir)
                .start()
            // Log reader exits naturally when the process exits.
            serviceScope.launch {
                dropProcess?.inputStream?.bufferedReader()?.forEachLine { line ->
                    Log.d(TAG, "[drop] $line")
                    broadcastLog(line)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start drop-client: ${e.message}")
            broadcastLog("Failed to start drop-client: ${e.message}")
        }
    }

    // ─── DNS helpers ──────────────────────────────────────────────────────────

    private fun detectOperatorDns(): String {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        // activeNetwork is whatever Android routes new connections through.
        // Must check it first: allNetworks can include a background mobile connection
        // even when WiFi is active, causing us to return the wrong DNS.
        val activeNet = cm.activeNetwork
        if (activeNet != null) {
            val caps = cm.getNetworkCapabilities(activeNet)
            if (caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                val dns = cm.getLinkProperties(activeNet)?.dnsServers?.firstOrNull()?.hostAddress
                if (!dns.isNullOrEmpty()) return dns
            }
        }
        // Fallback: prefer WiFi over cellular
        for (transport in listOf(NetworkCapabilities.TRANSPORT_WIFI, NetworkCapabilities.TRANSPORT_CELLULAR)) {
            for (network in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(network) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                if (!caps.hasTransport(transport)) continue
                val dns = cm.getLinkProperties(network)?.dnsServers?.firstOrNull()?.hostAddress
                if (!dns.isNullOrEmpty()) return dns
            }
        }
        return "8.8.8.8"
    }

    /**
     * Returns the first DNS from [candidates] that successfully resolves [hostname],
     * or the last candidate as a last resort.
     */
    private suspend fun selectWorkingDns(hostname: String, candidates: List<String>): String {
        for (dns in candidates) {
            if (canResolveWithDns(hostname, dns)) {
                broadcastLog("DNS probe: $dns → $hostname ✓")
                return dns
            }
            broadcastLog("DNS probe: $dns → $hostname ✗")
        }
        return candidates.last()
    }

    private suspend fun canResolveWithDns(hostname: String, dnsServer: String): Boolean =
        withContext(Dispatchers.IO) {
            try {
                val socket = DatagramSocket()
                protect(socket) // bypass VPN routing so we hit the real network
                socket.soTimeout = 3000
                val query = buildDnsQuery(hostname)
                socket.send(DatagramPacket(query, query.size, InetAddress.getByName(dnsServer), 53))
                val buf = ByteArray(512)
                socket.receive(DatagramPacket(buf, buf.size))
                socket.close()
                // ANCOUNT is at offset 6–7; >0 means we got at least one answer
                val ancount = ((buf[6].toInt() and 0xFF) shl 8) or (buf[7].toInt() and 0xFF)
                ancount > 0
            } catch (_: Exception) {
                false
            }
        }

    private fun buildDnsQuery(hostname: String): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x12, 0x34))          // transaction ID
        out.write(byteArrayOf(0x01, 0x00))          // flags: standard query, recursion desired
        out.write(byteArrayOf(0x00, 0x01))          // QDCOUNT = 1
        out.write(byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) // AN/NS/AR = 0
        for (label in hostname.trimEnd('.').split(".")) {
            out.write(label.length)
            out.write(label.toByteArray())
        }
        out.write(0x00)                             // end of QNAME
        out.write(byteArrayOf(0x00, 0x01))          // QTYPE = A
        out.write(byteArrayOf(0x00, 0x01))          // QCLASS = IN
        return out.toByteArray()
    }

    private fun isPublicIp(ip: String): Boolean {
        val p = ip.split(".").mapNotNull { it.toIntOrNull() }
        if (p.size != 4) return false
        return !(p[0] == 10 ||
                 p[0] == 127 ||
                 (p[0] == 172 && p[1] in 16..31) ||
                 (p[0] == 192 && p[1] == 168) ||
                 (p[0] == 169 && p[1] == 254))
    }

    // ─── Notifications ────────────────────────────────────────────────────────

    private fun createNotificationChannel() {
        val ch = NotificationChannel(
            CHANNEL_ID, "DROP VPN", NotificationManager.IMPORTANCE_LOW
        ).apply { description = "VPN tunnel status"; setShowBadge(false) }
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    private fun buildNotification(status: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this, 10,
            Intent(this, OlcVpnService::class.java).apply { action = ACTION_STOP_VPN },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val (title, text) = when (status) {
            STATUS_VPN_UP       -> "DROP VPN активен"   to "Весь трафик через DROP"
            STATUS_VPN_STARTING -> "Запуск VPN..."       to "Настройка туннеля"
            STATUS_VPN_ERROR    -> "VPN ошибка"          to "Остановите и попробуйте снова"
            else                -> "VPN отключён"        to "DROP неактивен"
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title).setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openIntent).setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(android.R.drawable.ic_delete, "Стоп", stopIntent)
            .build()
    }

    private fun updateNotification(status: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(status))
    }

    // ─── Broadcasts ───────────────────────────────────────────────────────────

    fun broadcastStatus(status: String, message: String = "") {
        LocalBroadcastManager.getInstance(this).sendBroadcast(
            Intent(BROADCAST_VPN_STATUS).apply {
                putExtra("status", status); putExtra("message", message)
            }
        )
    }

    fun broadcastLog(line: String) {
        LocalBroadcastManager.getInstance(this).sendBroadcast(
            Intent(TunnelService.BROADCAST_LOG).apply { putExtra("line", line) }
        )
    }
}
