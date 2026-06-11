package xyz.olcrtc.android

import android.Manifest
import android.content.*
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.*
import android.provider.Settings
import android.text.method.ScrollingMovementMethod
import android.view.View
import android.view.animation.AnimationUtils
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import xyz.olcrtc.android.Prefs.autoStart
import xyz.olcrtc.android.Prefs.dnsServer
import xyz.olcrtc.android.Prefs.pubKey
import xyz.olcrtc.android.Prefs.psk
import xyz.olcrtc.android.Prefs.serverUrl
import xyz.olcrtc.android.Prefs.socksPort
import xyz.olcrtc.android.Prefs.vpnMode
import xyz.olcrtc.android.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private var proxyStatus = TunnelService.STATUS_DISCONNECTED
    private var vpnStatus   = OlcVpnService.STATUS_VPN_DOWN
    private val logBuffer   = ArrayDeque<String>(500)
    private val MAX_LOG_LINES = 300

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                TunnelService.BROADCAST_STATUS -> {
                    val status = intent.getStringExtra("status") ?: return
                    val msg    = intent.getStringExtra("message") ?: ""
                    val port   = intent.getIntExtra("port", 8808)
                    proxyStatus = status
                    updateUi()
                    if (msg.isNotBlank()) appendLog("[proxy] $msg")
                    if (status == TunnelService.STATUS_CONNECTED)
                        binding.tvProxyAddress.text = "SOCKS5 -> 127.0.0.1:$port"
                }
                OlcVpnService.BROADCAST_VPN_STATUS -> {
                    val status = intent.getStringExtra("status") ?: return
                    val msg    = intent.getStringExtra("message") ?: ""
                    vpnStatus = status
                    updateUi()
                    if (msg.isNotBlank()) appendLog("[vpn] $msg")
                }
                TunnelService.BROADCAST_LOG -> {
                    appendLog(intent.getStringExtra("line") ?: return)
                }
            }
        }
    }

    private val notifPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* not critical */ }

    private val vpnPermLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) launchVpnService()
        else Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setupUI()
        loadPrefs()
        checkBinariesAvailable()
        requestNotificationPermission()
        checkBatteryOptimization()
        handleDeepLink(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDeepLink(intent)
    }

    /**
     * Parses drop://HOSTNAME/PUBKEY/PSK deep links.
     * Example: drop://my.cdn.ru/0035e92d.../89d576f7...
     */
    private fun handleDeepLink(intent: Intent?) {
        val uri = intent?.data ?: return
        if (uri.scheme != "drop") return
        val host = uri.host ?: return
        val parts = uri.path?.split("/")?.filter { it.isNotEmpty() } ?: return
        if (parts.size < 2) return
        val pub = parts[0]
        val pskVal = parts[1]
        if (pub.length < 32 || pskVal.length < 16) return
        binding.etUrl.setText("https://$host/")
        binding.etPub.setText(pub)
        binding.etPsk.setText(pskVal)
        savePrefs()
        appendLog("Настройки загружены из ссылки ($host)")
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter().apply {
            addAction(TunnelService.BROADCAST_STATUS)
            addAction(TunnelService.BROADCAST_LOG)
            addAction(OlcVpnService.BROADCAST_VPN_STATUS)
        }
        LocalBroadcastManager.getInstance(this).registerReceiver(receiver, filter)
        checkBatteryOptimization()
    }

    override fun onPause() {
        LocalBroadcastManager.getInstance(this).unregisterReceiver(receiver)
        savePrefs()
        super.onPause()
    }

    private fun setupUI() {
        binding.tvLog.movementMethod = ScrollingMovementMethod()

        binding.btnPasteLink.setOnClickListener {
            val clip = (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager)
                .primaryClip?.getItemAt(0)?.text?.toString() ?: ""
            val text = clip.trim()
            // Support: drop://HOST/PUB/PSK  or  HOST/PUB/PSK  or  URL PUB PSK (space separated)
            val uri = when {
                text.startsWith("drop://") -> Uri.parse(text)
                text.startsWith("https://") || text.startsWith("http://") -> null
                else -> runCatching { Uri.parse("drop://$text") }.getOrNull()
            }
            if (uri != null && uri.host != null) {
                val parts = uri.path?.split("/")?.filter { it.isNotEmpty() } ?: emptyList()
                if (parts.size >= 2) {
                    binding.etUrl.setText("https://${uri.host}/")
                    binding.etPub.setText(parts[0])
                    binding.etPsk.setText(parts[1])
                    savePrefs()
                    Toast.makeText(this, "Настройки загружены", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
            }
            // Fallback: space-separated "URL PUB PSK"
            val sp = text.split("\\s+".toRegex())
            if (sp.size >= 3) {
                binding.etUrl.setText(sp[0])
                binding.etPub.setText(sp[1])
                binding.etPsk.setText(sp[2])
                savePrefs()
                Toast.makeText(this, "Настройки загружены", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            Toast.makeText(this, "Неверный формат. Ожидается drop://HOST/PUB/PSK", Toast.LENGTH_LONG).show()
        }

        binding.toggleMode.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) return@addOnButtonCheckedListener
            val wantsVpn = (checkedId == binding.btnModeVpn.id)
            vpnMode = wantsVpn
            updateModeHint()
            if (isAnyTunnelActive()) stopAll()
        }

        binding.btnConnect.setOnClickListener {
            if (isAnyTunnelActive()) stopAll()
            else if (vpnMode) startVpnMode() else startProxyMode()
        }

        binding.btnCopyProxy.setOnClickListener {
            val port  = binding.etPort.text.toString().toIntOrNull() ?: 8808
            val proxy = "socks5h://127.0.0.1:$port"
            (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager)
                .setPrimaryClip(ClipData.newPlainText("proxy", proxy))
            Toast.makeText(this, "Copied: $proxy", Toast.LENGTH_SHORT).show()
        }

        binding.btnClearLog.setOnClickListener { logBuffer.clear(); binding.tvLog.text = "" }
        binding.btnCopyLog.setOnClickListener { copyLogToClipboard() }

        binding.cardLogHeader.setOnClickListener {
            val v = binding.tvLog.visibility == View.VISIBLE
            binding.tvLog.visibility       = if (v) View.GONE else View.VISIBLE
            binding.btnClearLog.visibility = if (v) View.GONE else View.VISIBLE
            binding.ivLogArrow.rotation    = if (v) 0f else 180f
        }

        binding.switchAutostart.setOnCheckedChangeListener { _, checked -> autoStart = checked }
        binding.btnBatteryFix.setOnClickListener { requestBatteryOptimizationExemption() }
        updateUi()
    }

    private fun loadPrefs() {
        binding.etUrl.setText(serverUrl)
        binding.etPub.setText(pubKey)
        binding.etPsk.setText(psk)
        binding.etPort.setText(socksPort.toString())
        binding.etDns.setText(dnsServer)
        binding.switchAutostart.isChecked = autoStart
        binding.toggleMode.check(if (vpnMode) binding.btnModeVpn.id else binding.btnModeProxy.id)
        updateModeHint()
    }

    private fun savePrefs() {
        serverUrl = binding.etUrl.text.toString().trim().let {
            if (it.isNotBlank() && !it.endsWith("/")) "$it/" else it
        }
        pubKey    = binding.etPub.text.toString().trim()
        psk       = binding.etPsk.text.toString().trim()
        socksPort = binding.etPort.text.toString().toIntOrNull() ?: 8808
        dnsServer = binding.etDns.text.toString().trim().ifBlank { "8.8.8.8" }
    }

    private fun updateModeHint() {
        if (vpnMode) {
            binding.tvModeHint.text = "VPN: весь трафик устройства через туннель"
            binding.cardDns.visibility = View.VISIBLE
        } else {
            binding.tvModeHint.text = "Прокси: SOCKS5 127.0.0.1:${binding.etPort.text.toString().ifBlank { "8808" }}"
            binding.cardDns.visibility = View.GONE
        }
    }

    private fun startProxyMode() {
        val url  = binding.etUrl.text.toString().trim()
        val pub  = binding.etPub.text.toString().trim()
        val pskV = binding.etPsk.text.toString().trim()
        val port = binding.etPort.text.toString().toIntOrNull() ?: 8808
        if (!validateInputs(url, pub, pskV)) return
        savePrefs()
        ContextCompat.startForegroundService(this,
            Intent(this, TunnelService::class.java).apply {
                action = TunnelService.ACTION_START
                putExtra(TunnelService.EXTRA_URL,  url)
                putExtra(TunnelService.EXTRA_PUB,  pub)
                putExtra(TunnelService.EXTRA_PSK,  pskV)
                putExtra(TunnelService.EXTRA_PORT, port)
            })
    }

    private fun startVpnMode() {
        val url  = binding.etUrl.text.toString().trim()
        val pub  = binding.etPub.text.toString().trim()
        val pskV = binding.etPsk.text.toString().trim()
        if (!validateInputs(url, pub, pskV)) return
        savePrefs()
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) vpnPermLauncher.launch(vpnIntent) else launchVpnService()
    }

    private fun launchVpnService() {
        ContextCompat.startForegroundService(this,
            Intent(this, OlcVpnService::class.java).apply {
                action = OlcVpnService.ACTION_START_VPN
                putExtra(OlcVpnService.EXTRA_URL,  binding.etUrl.text.toString().trim())
                putExtra(OlcVpnService.EXTRA_PUB,  binding.etPub.text.toString().trim())
                putExtra(OlcVpnService.EXTRA_PSK,  binding.etPsk.text.toString().trim())
                putExtra(OlcVpnService.EXTRA_PORT, binding.etPort.text.toString().toIntOrNull() ?: 8808)
                putExtra(OlcVpnService.EXTRA_DNS,  binding.etDns.text.toString().trim().ifBlank { "8.8.8.8" })
            })
        vpnStatus = OlcVpnService.STATUS_VPN_STARTING
        updateUi()
    }

    private fun stopAll() {
        startService(Intent(this, TunnelService::class.java).apply { action = TunnelService.ACTION_STOP })
        startService(Intent(this, OlcVpnService::class.java).apply { action = OlcVpnService.ACTION_STOP_VPN })
        stopService(Intent(this, TunnelService::class.java))
        stopService(Intent(this, OlcVpnService::class.java))
        getSystemService(android.app.NotificationManager::class.java).apply {
            cancel(TunnelService.NOTIFICATION_ID)
            cancel(OlcVpnService.NOTIFICATION_ID)
        }
        proxyStatus = TunnelService.STATUS_DISCONNECTED
        vpnStatus   = OlcVpnService.STATUS_VPN_DOWN
        updateUi()
    }

    private fun isAnyTunnelActive() =
        proxyStatus == TunnelService.STATUS_CONNECTED    ||
        proxyStatus == TunnelService.STATUS_CONNECTING   ||
        vpnStatus   == OlcVpnService.STATUS_VPN_UP       ||
        vpnStatus   == OlcVpnService.STATUS_VPN_STARTING ||
        vpnStatus   == OlcVpnService.STATUS_VPN_ERROR

    private fun updateUi() {
        val isVpn    = vpnMode
        val isActive = isAnyTunnelActive()

        val (statusText, statusColor) = when {
            isVpn && vpnStatus == OlcVpnService.STATUS_VPN_UP       -> "VPN активен"        to getColor(android.R.color.holo_green_dark)
            isVpn && vpnStatus == OlcVpnService.STATUS_VPN_STARTING  -> "Запуск VPN..."       to getColor(android.R.color.holo_orange_dark)
            isVpn && vpnStatus == OlcVpnService.STATUS_VPN_ERROR     -> "VPN ошибка"          to getColor(android.R.color.holo_red_dark)
            !isVpn && proxyStatus == TunnelService.STATUS_CONNECTED  -> "Прокси активен"      to getColor(android.R.color.holo_green_dark)
            !isVpn && proxyStatus == TunnelService.STATUS_CONNECTING -> "Подключение..."      to getColor(android.R.color.holo_orange_dark)
            !isVpn && proxyStatus == TunnelService.STATUS_ERROR      -> "Ошибка"              to getColor(android.R.color.holo_red_dark)
            else                                                      -> "Не подключено"       to getColor(android.R.color.darker_gray)
        }
        binding.tvStatus.text = statusText
        binding.tvStatus.setTextColor(statusColor)
        binding.btnConnect.text = if (isActive) "Отключить" else "Подключить"
        binding.btnConnect.setBackgroundColor(
            if (isActive) getColor(android.R.color.holo_red_light)
            else getColor(com.google.android.material.R.color.material_dynamic_primary40)
        )
        binding.cardProxy.visibility     = if (!isVpn && proxyStatus == TunnelService.STATUS_CONNECTED) View.VISIBLE else View.GONE
        binding.cardVpnActive.visibility = if (isVpn && vpnStatus == OlcVpnService.STATUS_VPN_UP) View.VISIBLE else View.GONE

        val connecting = proxyStatus == TunnelService.STATUS_CONNECTING || vpnStatus == OlcVpnService.STATUS_VPN_STARTING
        if (connecting) binding.tvStatus.startAnimation(AnimationUtils.loadAnimation(this, android.R.anim.fade_in))
        else binding.tvStatus.clearAnimation()

        binding.toggleMode.isEnabled   = !isActive
        binding.btnModeProxy.isEnabled = !isActive
        binding.btnModeVpn.isEnabled   = !isActive
    }

    private fun appendLog(line: String) {
        logBuffer.addLast(line)
        while (logBuffer.size > MAX_LOG_LINES) logBuffer.removeFirst()
        val ts = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date())
        runOnUiThread {
            binding.tvLog.append("[$ts] $line\n")
            val scroll = binding.tvLog.layout?.let {
                it.getLineTop(binding.tvLog.lineCount) - binding.tvLog.height
            } ?: 0
            if (scroll > 0) binding.tvLog.scrollTo(0, scroll)
        }
    }

    private fun copyLogToClipboard() {
        if (logBuffer.isEmpty()) { Toast.makeText(this, "Log is empty", Toast.LENGTH_SHORT).show(); return }
        val cb = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        cb.setPrimaryClip(ClipData.newPlainText("DROP log", logBuffer.joinToString("\n")))
        Toast.makeText(this, "Log copied (${logBuffer.size} lines)", Toast.LENGTH_SHORT).show()
    }

    private fun validateInputs(url: String, pub: String, psk: String): Boolean {
        var ok = true
        if (url.isBlank())  { binding.tilUrl.error  = "Введите URL сервера"; ok = false } else binding.tilUrl.error  = null
        if (pub.isBlank())  { binding.tilPub.error  = "Введите публичный ключ"; ok = false } else binding.tilPub.error  = null
        if (psk.isBlank())  { binding.tilPsk.error  = "Введите PSK"; ok = false } else binding.tilPsk.error  = null
        return ok
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun checkBatteryOptimization() {
        val pm = getSystemService(PowerManager::class.java)
        binding.cardBatteryWarning.visibility =
            if (!pm.isIgnoringBatteryOptimizations(packageName)) View.VISIBLE else View.GONE
    }

    private fun requestBatteryOptimizationExemption() {
        startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
            data = Uri.parse("package:$packageName")
        })
    }

    private fun checkBinariesAvailable() {
        if (!BinaryManager.isBinaryAvailable(this)) {
            AlertDialog.Builder(this)
                .setTitle("drop binary not found")
                .setMessage("Build libdrop.so and place in jniLibs/arm64-v8a/")
                .setPositiveButton("OK", null).show()
        }
        binding.tvVpnBinaryWarning.visibility = View.GONE
    }
}
