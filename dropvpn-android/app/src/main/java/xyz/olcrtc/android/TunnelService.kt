package xyz.olcrtc.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import kotlinx.coroutines.*
import xyz.olcrtc.android.Prefs.dnsServer
import java.io.BufferedReader
import java.io.InputStreamReader

class TunnelService : LifecycleService() {

    companion object {
        private const val TAG = "TunnelService"
        const val CHANNEL_ID      = "drop_tunnel"
        const val NOTIFICATION_ID = 1

        const val ACTION_START = "xyz.drop.START"
        const val ACTION_STOP  = "xyz.drop.STOP"

        const val EXTRA_URL  = "server_url"
        const val EXTRA_PUB  = "pub_key"
        const val EXTRA_PSK  = "psk"
        const val EXTRA_PORT = "socks_port"

        const val BROADCAST_STATUS = "xyz.drop.STATUS"
        const val BROADCAST_LOG    = "xyz.drop.LOG"

        const val STATUS_CONNECTING   = "CONNECTING"
        const val STATUS_CONNECTED    = "CONNECTED"
        const val STATUS_DISCONNECTED = "DISCONNECTED"
        const val STATUS_ERROR        = "ERROR"

        private const val RECONNECT_DELAY_MS     = 3000L
        private const val MAX_RECONNECT_DELAY_MS = 60000L
    }

    private var tunnelProcess: Process? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var processJob: Job? = null
    private var reconnectDelay = RECONNECT_DELAY_MS
    private var isRunning = false

    private var serverUrl = ""
    private var pubKey    = ""
    private var psk       = ""
    private var socksPort = 8808

    private val connectivityManager by lazy {
        getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.i(TAG, "Network available — restarting tunnel")
            if (isRunning) tunnelProcess?.destroy()
        }
        override fun onLost(network: Network) {
            Log.i(TAG, "Network lost — killing process for reconnect")
            if (isRunning) tunnelProcess?.destroy()
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        acquireWakeLock()
        try {
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            connectivityManager.registerNetworkCallback(req, networkCallback)
        } catch (e: Exception) {
            Log.w(TAG, "registerNetworkCallback: ${e.message}")
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)

        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            stopForeground(STOP_FOREGROUND_REMOVE)
            getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
            stopSelf()
            return START_NOT_STICKY
        }

        if (intent?.action == ACTION_START) {
            serverUrl = intent.getStringExtra(EXTRA_URL)  ?: ""
            pubKey    = intent.getStringExtra(EXTRA_PUB)  ?: ""
            psk       = intent.getStringExtra(EXTRA_PSK)  ?: ""
            socksPort = intent.getIntExtra(EXTRA_PORT, 8808)
            if (serverUrl.isBlank() || pubKey.isBlank() || psk.isBlank()) {
                broadcastStatus(STATUS_ERROR, "Server URL, public key or PSK is empty")
                stopSelf()
                return START_NOT_STICKY
            }
        }

        startForeground(NOTIFICATION_ID, buildNotification(STATUS_CONNECTING))
        if (!isRunning) startTunnel()
        return START_STICKY
    }

    override fun onBind(intent: Intent): IBinder? {
        super.onBind(intent)
        return null
    }

    override fun onDestroy() {
        stopTunnel()
        try { connectivityManager.unregisterNetworkCallback(networkCallback) } catch (_: Exception) {}
        releaseWakeLock()
        super.onDestroy()
    }

    private fun startTunnel() {
        if (isRunning) return
        isRunning = true
        reconnectDelay = RECONNECT_DELAY_MS

        processJob = lifecycleScope.launch(Dispatchers.IO) {
            while (isRunning) {
                runProcess()
                if (isRunning) {
                    broadcastStatus(STATUS_CONNECTING, "Reconnecting in ${reconnectDelay / 1000}s...")
                    updateNotification(STATUS_CONNECTING)
                    delay(reconnectDelay)
                    reconnectDelay = minOf(reconnectDelay * 2, MAX_RECONNECT_DELAY_MS)
                }
            }
        }
    }

    private fun stopTunnel() {
        isRunning = false
        processJob?.cancel()
        processJob = null
        tunnelProcess?.destroy()
        tunnelProcess = null
        broadcastStatus(STATUS_DISCONNECTED)
    }

    private suspend fun runProcess() {
        val binary = try {
            BinaryManager.getBinary(this@TunnelService)
        } catch (e: Exception) {
            broadcastStatus(STATUS_ERROR, "Binary not found: ${e.message}")
            return
        }

        // Use operator's DNS if it's public (e.g. Megafon blocks 8.8.8.8:53),
        // otherwise use the DNS from settings (default 8.8.8.8).
        val savedDns = dnsServer.ifBlank { "8.8.8.8" }
        val operatorDns = detectOperatorDns()
        val dns = if (isPublicIp(operatorDns)) operatorDns else savedDns
        val cmd = BinaryManager.buildCommand(binary.absolutePath, serverUrl, pubKey, psk, socksPort, dns)
        broadcastLog("Starting DROP -> SOCKS5 127.0.0.1:$socksPort (DNS $dns)")

        try {
            val process = ProcessBuilder(cmd)
                .redirectErrorStream(true)
                .directory(filesDir)
                .start()
            tunnelProcess = process
            reconnectDelay = RECONNECT_DELAY_MS
            broadcastStatus(STATUS_CONNECTED)
            updateNotification(STATUS_CONNECTED)

            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?
            while (reader.readLine().also { line = it } != null && isRunning) {
                val l = line!!
                Log.d(TAG, "[drop] $l")
                broadcastLog(l)
                if (l.contains("session up", ignoreCase = true)) {
                    broadcastStatus(STATUS_CONNECTED)
                    updateNotification(STATUS_CONNECTED)
                }
            }
            process.waitFor()

        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            broadcastLog("Error: ${e.message}")
            broadcastStatus(STATUS_ERROR, e.message ?: "Unknown error")
        } finally {
            tunnelProcess?.destroy()
            tunnelProcess = null
        }
    }

    private fun createNotificationChannel() {
        val ch = NotificationChannel(CHANNEL_ID, "DROP Tunnel", NotificationManager.IMPORTANCE_LOW)
            .apply { description = "Tunnel status"; setShowBadge(false) }
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    private fun buildNotification(status: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, TunnelService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val isActive = status == STATUS_CONNECTED || status == STATUS_CONNECTING || status == STATUS_ERROR
        val (title, text, icon) = when (status) {
            STATUS_CONNECTED  -> Triple("DROP активен",       "SOCKS5 127.0.0.1:$socksPort", android.R.drawable.presence_online)
            STATUS_CONNECTING -> Triple("Подключение...",     "Установка соединения",         android.R.drawable.presence_away)
            STATUS_ERROR      -> Triple("DROP ошибка",        "Переподключение...",           android.R.drawable.presence_busy)
            else              -> Triple("DROP отключён",      "Туннель неактивен",            android.R.drawable.presence_offline)
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(icon)
            .setContentIntent(openIntent)
            .setOngoing(isActive)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .apply { if (isActive) addAction(android.R.drawable.ic_delete, "Стоп", stopIntent) }
            .build()
    }

    private fun updateNotification(status: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(status))
    }

    private fun broadcastStatus(status: String, message: String = "") {
        LocalBroadcastManager.getInstance(this).sendBroadcast(
            Intent(BROADCAST_STATUS).apply {
                putExtra("status", status)
                putExtra("message", message)
                putExtra("port", socksPort)
            }
        )
    }

    private fun broadcastLog(line: String) {
        LocalBroadcastManager.getInstance(this).sendBroadcast(
            Intent(BROADCAST_LOG).apply { putExtra("line", line) }
        )
    }

    private fun detectOperatorDns(): String {
        for (network in connectivityManager.allNetworks) {
            val caps = connectivityManager.getNetworkCapabilities(network) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            val dns = connectivityManager.getLinkProperties(network)?.dnsServers
                ?.firstOrNull()?.hostAddress
            if (!dns.isNullOrEmpty()) return dns
        }
        return "8.8.8.8"
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

    private fun acquireWakeLock() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "drop:TunnelWakeLock")
            .also { it.acquire() }
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }
}
