package xyz.olcrtc.android

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

object Prefs {
    private const val NAME = "drop_prefs"

    private fun sp(context: Context): SharedPreferences =
        context.getSharedPreferences(NAME, Context.MODE_PRIVATE)

    var Context.serverUrl: String
        get() = sp(this).getString("server_url", "") ?: ""
        set(v) = sp(this).edit { putString("server_url", v) }

    var Context.pubKey: String
        get() = sp(this).getString("pub_key", "") ?: ""
        set(v) = sp(this).edit { putString("pub_key", v) }

    var Context.psk: String
        get() = sp(this).getString("psk", "") ?: ""
        set(v) = sp(this).edit { putString("psk", v) }

    var Context.socksPort: Int
        get() = sp(this).getInt("socks_port", 8808)
        set(v) = sp(this).edit { putInt("socks_port", v) }

    var Context.autoStart: Boolean
        get() = sp(this).getBoolean("autostart", false)
        set(v) = sp(this).edit { putBoolean("autostart", v) }

    /** true = VPN mode (all traffic), false = proxy mode (SOCKS5 only) */
    var Context.vpnMode: Boolean
        get() = sp(this).getBoolean("vpn_mode", false)
        set(v) = sp(this).edit { putBoolean("vpn_mode", v) }

    /** DNS server used in VPN mode */
    var Context.dnsServer: String
        get() = sp(this).getString("dns_server", "8.8.8.8") ?: "8.8.8.8"
        set(v) = sp(this).edit { putString("dns_server", v) }
}
