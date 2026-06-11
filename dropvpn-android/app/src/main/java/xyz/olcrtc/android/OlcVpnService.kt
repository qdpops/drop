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

    private var tunFd:       ParcelFileDescriptor? = null
    private var dropProcess: Process? = null
    private var isRunning = false

    private var serverUrl = ""
    private var pubKey    = ""
    private var psk       = ""
    private var socksPort = 8808
    private var dnsServer = "8.8.8.8"

    // ─── Lifecycle ────────────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
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
                dnsServer = intent.getStringExtra(EXTRA_DNS)  ?: "8.8.8.8"
            }
        }
        startForeground(NOTIFICATION_ID, buildNotification(STATUS_VPN_STARTING))
        serviceScope.launch { startVpn() }
        return START_STICKY
    }

    override fun onRevoke() {
        stopVpn()
        stopForeground(STOP_FOREGROUND_REMOVE)
        getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        stopForeground(STOP_FOREGROUND_REMOVE)
        getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        serviceScope.cancel()
        super.onDestroy()
    }

    // ─── VPN lifecycle ────────────────────────────────────────────────────────

    private suspend fun startVpn() {
        isRunning = true
        broadcastStatus(STATUS_VPN_STARTING)

        val dropBinary = try {
            BinaryManager.getBinary(this)
        } catch (e: Exception) {
            broadcastStatus(STATUS_VPN_ERROR, "drop binary not found: ${e.message}")
            return
        }

        // Detect the operator's DNS before the VPN is up. This bypasses any
        // operator-level blocking of 8.8.8.8 (e.g. Megafon).
        val effectiveDns = detectOperatorDns()
        broadcastLog("Operator DNS: $effectiveDns")

        startDropProcess(dropBinary.absolutePath, effectiveDns)
        broadcastLog("Waiting for SOCKS5 server...")
        delay(2000)  // give drop-client time to connect

        val fd = buildTunInterface(effectiveDns) ?: run {
            broadcastStatus(STATUS_VPN_ERROR, "Failed to create TUN interface")
            return
        }
        tunFd = fd
        broadcastLog("TUN fd=${fd.fd} created")

        val forwarder = TunPacketForwarder(
            vpnService = this,
            tunFd      = fd,
            socksPort  = socksPort,
            dnsServer  = effectiveDns,
            onLog      = { line -> broadcastLog(line) },
            scope      = serviceScope
        )
        forwarder.start()

        broadcastStatus(STATUS_VPN_UP)
        updateNotification(STATUS_VPN_UP)
        Log.i(TAG, "VPN UP — in-process forwarder active, SOCKS5 127.0.0.1:$socksPort, DNS $effectiveDns")
    }

    /**
     * Returns the DNS server currently assigned by the operator (from the active
     * non-VPN network's LinkProperties). Called before the VPN interface is created
     * so [ConnectivityManager.allNetworks] still reflects the underlying network.
     * Falls back to 8.8.8.8 if nothing is found.
     */
    private fun detectOperatorDns(): String {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        for (network in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            val dns = cm.getLinkProperties(network)?.dnsServers
                ?.firstOrNull()?.hostAddress
            if (!dns.isNullOrEmpty()) return dns
        }
        return "8.8.8.8"
    }

    private fun stopVpn() {
        isRunning = false
        dropProcess?.destroy(); dropProcess = null
        tunFd?.close();         tunFd       = null
        serviceScope.coroutineContext[Job]?.cancelChildren()
        broadcastStatus(STATUS_VPN_DOWN)
        updateNotification(STATUS_VPN_DOWN)
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
