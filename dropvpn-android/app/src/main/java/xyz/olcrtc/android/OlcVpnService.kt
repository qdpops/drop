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

        const val ACTION_FINISH_APP  = "xyz.drop.FINISH_APP"
        const val EXTRA_FINISH_APP   = "finish_app"

        // Readable by MainActivity without waiting for the next broadcast — covers
        // Activity recreation, screen-off resume, and START_STICKY restarts.
        @Volatile var currentStatus: String = STATUS_VPN_DOWN

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

    @Volatile private var tunFd:           ParcelFileDescriptor? = null
    @Volatile private var dropProcess:     Process? = null
    @Volatile private var isRunning        = false
    @Volatile private var localDnsProxy:   LocalDnsProxy? = null
    @Volatile private var activeNetwork:   android.net.Network? = null
    private var vpnJob: Job? = null

    private var serverUrl = ""
    private var pubKey    = ""
    private var psk       = ""
    private var socksPort = 8808
    private var dnsServer = ""

    // Restart only on a genuine network switch (different Network object).
    // onAvailable can fire repeatedly for the same network on some operators
    // (e.g. MTS transitions LTE idle→active under load) — those must be ignored
    // or the session enters a restart loop.
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: android.net.Network) {
            val prev = activeNetwork
            activeNetwork = network
            if (isRunning && prev != null && prev != network) {
                broadcastLog("Смена сети — перезапуск VPN")
                Log.i(TAG, "Network changed ($prev → $network) — killing session for reconnect")
                // Capture before nulling: @Volatile read + call is not atomic,
                // so a concurrent assignment between the read and the call would
                // operate on the wrong object.
                val proc = dropProcess; if (proc != null) { dropProcess = null; proc.destroy() }
                val fd   = tunFd;   if (fd != null) { tunFd = null; fd.close() }
            }
        }

        override fun onLost(network: android.net.Network) {
            if (network == activeNetwork) activeNetwork = null
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
                // startActivity before stopForeground: the foreground-service exemption
                // for background activity launches is revoked by stopForeground on
                // Android 10+, so the call must happen while we are still foreground.
                if (intent.getBooleanExtra(EXTRA_FINISH_APP, false)) {
                    startActivity(Intent(this@OlcVpnService, MainActivity::class.java).apply {
                        action = ACTION_FINISH_APP
                        addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or
                                 Intent.FLAG_ACTIVITY_SINGLE_TOP or
                                 Intent.FLAG_ACTIVITY_NEW_TASK)
                    })
                }
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
        // START_STICKY restart delivers intent=null — params are empty because they
        // came from Intent extras, not persisted storage. Read from SharedPreferences
        // so the reconnect loop can restart with the correct configuration.
        if (serverUrl.isEmpty()) restoreParamsFromPrefs()
        startForeground(NOTIFICATION_ID, buildNotification(STATUS_VPN_STARTING))
        // Cancel existing loop and eagerly kill the drop process so its port is
        // released before the new session starts. The finally block in runVpnSession
        // also does this, but may not complete before the new coroutine is scheduled.
        vpnJob?.cancel()
        dropProcess?.destroy(); dropProcess = null
        tunFd?.close();         tunFd       = null
        vpnJob = serviceScope.launch { startVpn() }
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
        // publicDns: pushed via addDnsServer() — what devices behind the VPN use.
        // The manual DNS field controls this; falls back to 8.8.8.8 when blank or
        // set to a carrier-local IP that is not reachable from the DROP server.
        val publicDns = dnsServer.takeIf { it.isNotBlank() && isPublicIp(it) } ?: "8.8.8.8"

        // resolverDns: always LocalDnsProxy (127.0.0.1:PORT).
        // Go's raw UDP sockets lose routing to the carrier DNS after TUN is
        // established — even addDisallowedApplication doesn't fully protect them
        // on all devices. LocalDnsProxy resolves via Android's InetAddress, which
        // is always correctly routed by the OS regardless of VPN state.
        val proxy = localDnsProxy ?: LocalDnsProxy { broadcastLog(it) }.also {
            it.start(serviceScope)
            localDnsProxy = it
        }
        val resolverDns = "127.0.0.1:${proxy.port}"
        broadcastLog("DNS: tunnel=$publicDns resolver=$resolverDns")

        val ownProcess = startDropProcess(binaryPath, resolverDns)
        broadcastLog("Waiting for SOCKS5 server...")
        // Poll until the SOCKS5 port is open rather than sleeping a fixed interval.
        val deadline = System.currentTimeMillis() + 5_000
        while (System.currentTimeMillis() < deadline) {
            try {
                java.net.Socket("127.0.0.1", socksPort).close()
                break
            } catch (_: Exception) { delay(100) }
        }

        val fd = buildTunInterface(publicDns)
        if (fd == null) {
            broadcastStatus(STATUS_VPN_ERROR, "Failed to create TUN interface")
            ownProcess?.destroy()
            if (dropProcess === ownProcess) dropProcess = null
            return
        }
        tunFd = fd
        broadcastLog("TUN fd=${fd.fd} created")

        TunPacketForwarder(
            vpnService   = this,
            tunFd        = fd,
            socksPort    = socksPort,
            dnsServer    = publicDns,
            dnsProxyPort = proxy.port,
            onLog        = { line -> broadcastLog(line) },
            scope        = serviceScope
        ).start()

        broadcastStatus(STATUS_VPN_UP)
        updateNotification(STATUS_VPN_UP)
        Log.i(TAG, "VPN UP — SOCKS5 127.0.0.1:$socksPort DNS $publicDns resolver $resolverDns")

        // Suspend here until drop-client exits (network change, error, or user stop).
        // finally guarantees cleanup even when the coroutine is cancelled (e.g. by
        // vpnJob?.cancel() in onStartCommand) — without it CancellationException
        // skips the cleanup block and leaves the process alive holding port 8808.
        try {
            withContext(Dispatchers.IO) { ownProcess?.waitFor() }
        } finally {
            // Destroy only OUR process. If onStartCommand replaced dropProcess
            // with a new session's process before our finally runs, leave it alone.
            ownProcess?.destroy()
            if (dropProcess === ownProcess) dropProcess = null
            // Same for tunFd: null the field only if nobody replaced it yet.
            if (tunFd === fd) tunFd = null
            try { fd.close() } catch (_: Exception) {}
            broadcastStatus(STATUS_VPN_DOWN)
            updateNotification(STATUS_VPN_DOWN)
            broadcastLog("VPN сессия завершена")
        }
    }

    private fun restoreParamsFromPrefs() {
        val sp = getSharedPreferences("drop_prefs", Context.MODE_PRIVATE)
        serverUrl = sp.getString("server_url", "") ?: ""
        pubKey    = sp.getString("pub_key",    "") ?: ""
        psk       = sp.getString("psk",        "") ?: ""
        socksPort = sp.getInt   ("socks_port", 8808)
        dnsServer = sp.getString("dns_server", "") ?: ""
    }

    // ─── Stop (user-initiated) ────────────────────────────────────────────────

    private fun stopVpn() {
        isRunning = false
        vpnJob?.cancel();       vpnJob        = null
        dropProcess?.destroy(); dropProcess   = null
        tunFd?.close();         tunFd         = null
        localDnsProxy?.stop();  localDnsProxy = null
        activeNetwork = null
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

    private fun startDropProcess(binaryPath: String, dns: String): Process? {
        val cmd = BinaryManager.buildCommand(binaryPath, serverUrl, pubKey, psk, socksPort, dns)
        Log.i(TAG, "Starting drop-client: ${cmd.joinToString(" ") { if (it == psk) "***" else it }}")
        return try {
            ProcessBuilder(cmd)
                .redirectErrorStream(true)
                .directory(filesDir)
                .start()
                .also { proc ->
                    dropProcess = proc
                    // Log reader exits naturally when the process exits.
                    serviceScope.launch {
                        proc.inputStream.bufferedReader().forEachLine { line ->
                            Log.d(TAG, "[drop] $line")
                            broadcastLog(line)
                        }
                    }
                }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start drop-client: ${e.message}")
            broadcastLog("Failed to start drop-client: ${e.message}")
            null
        }
    }

    // ─── DNS helpers ──────────────────────────────────────────────────────────

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
            Intent(this, OlcVpnService::class.java).apply {
                action = ACTION_STOP_VPN
                putExtra(EXTRA_FINISH_APP, true)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val (title, text) = when (status) {
            STATUS_VPN_UP       -> "DROP VPN активен"   to "Весь трафик через DROP"
            STATUS_VPN_STARTING -> "Запуск VPN..."       to "Настройка туннеля"
            STATUS_VPN_ERROR    -> "VPN ошибка"          to "Остановите и попробуйте снова"
            else                -> "VPN отключён"        to "DROP неактивен"
        }
        val isActive = status != STATUS_VPN_DOWN
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title).setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openIntent).setOngoing(isActive)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .apply { if (isActive) addAction(android.R.drawable.ic_delete, "Стоп", stopIntent) }
            .build()
    }

    private fun updateNotification(status: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(status))
    }

    // ─── Broadcasts ───────────────────────────────────────────────────────────

    fun broadcastStatus(status: String, message: String = "") {
        currentStatus = status
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
