package xyz.olcrtc.android

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import xyz.olcrtc.android.Prefs.autoStart
import xyz.olcrtc.android.Prefs.dnsServer
import xyz.olcrtc.android.Prefs.pubKey
import xyz.olcrtc.android.Prefs.psk
import xyz.olcrtc.android.Prefs.serverUrl
import xyz.olcrtc.android.Prefs.socksPort
import xyz.olcrtc.android.Prefs.vpnMode

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != "android.intent.action.QUICKBOOT_POWERON") return

        if (!context.autoStart) return
        if (context.serverUrl.isBlank() || context.pubKey.isBlank() || context.psk.isBlank()) return

        if (context.vpnMode) {
            ContextCompat.startForegroundService(context,
                Intent(context, OlcVpnService::class.java).apply {
                    action = OlcVpnService.ACTION_START_VPN
                    putExtra(OlcVpnService.EXTRA_URL,  context.serverUrl)
                    putExtra(OlcVpnService.EXTRA_PUB,  context.pubKey)
                    putExtra(OlcVpnService.EXTRA_PSK,  context.psk)
                    putExtra(OlcVpnService.EXTRA_PORT, context.socksPort)
                    putExtra(OlcVpnService.EXTRA_DNS,  context.dnsServer)
                })
        } else {
            ContextCompat.startForegroundService(context,
                Intent(context, TunnelService::class.java).apply {
                    action = TunnelService.ACTION_START
                    putExtra(TunnelService.EXTRA_URL,  context.serverUrl)
                    putExtra(TunnelService.EXTRA_PUB,  context.pubKey)
                    putExtra(TunnelService.EXTRA_PSK,  context.psk)
                    putExtra(TunnelService.EXTRA_PORT, context.socksPort)
                })
        }
    }
}
