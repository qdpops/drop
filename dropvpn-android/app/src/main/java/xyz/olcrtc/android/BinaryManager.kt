package xyz.olcrtc.android

import android.content.Context
import android.util.Log
import java.io.File

/**
 * Manages the drop-client binary shipped as libdrop.so in jniLibs/arm64-v8a/.
 *
 * Android extracts it to nativeLibraryDir on install — the only location
 * where SELinux allows execve() on non-rooted Android 10+ devices.
 *
 * Build (from the dropt/ directory):
 *   GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
 *     go build -ldflags="-s -w" -trimpath \
 *     -o ../olcrtc-android/app/src/main/jniLibs/arm64-v8a/libdrop.so \
 *     ./cmd/client
 */
object BinaryManager {

    private const val TAG      = "BinaryManager"
    private const val LIB_NAME = "libdrop.so"

    fun getBinary(context: Context): File {
        val dir    = context.applicationInfo.nativeLibraryDir
        val binary = File(dir, LIB_NAME)

        if (!binary.exists()) {
            error("$LIB_NAME not found in nativeLibraryDir ($dir). " +
                  "Rebuild APK with $LIB_NAME in jniLibs/arm64-v8a/.")
        }

        if (!binary.canExecute()) {
            Log.w(TAG, "$LIB_NAME not executable — attempting chmod")
            binary.setExecutable(true, false)
        }

        Log.d(TAG, "Binary: ${binary.absolutePath} (${binary.length()} bytes, exec=${binary.canExecute()})")
        return binary
    }

    fun isBinaryAvailable(context: Context): Boolean {
        val dir = context.applicationInfo.nativeLibraryDir
        return File(dir, LIB_NAME).exists()
    }

    /**
     * Builds the drop-client command line.
     *  -url  : full server URL (may be IP-based if hostname was pre-resolved by Kotlin)
     *  -pub  : server static public key (64-char hex)
     *  -psk  : pre-shared key (32-char hex)
     *  -socks: local SOCKS5 listen address
     *  -dns  : DNS resolver for the server hostname (omitted when URL already uses a raw IP)
     *  -host : TLS SNI + Host header override (set when URL contains a raw IP)
     */
    fun buildCommand(
        path: String, url: String, pubKey: String, psk: String, port: Int,
        dns: String, hostOverride: String = ""
    ): List<String> {
        val cmd = mutableListOf(path, "-url", url, "-pub", pubKey, "-psk", psk, "-socks", "127.0.0.1:$port")
        if (dns.isNotEmpty()) cmd.addAll(listOf("-dns", dns))
        if (hostOverride.isNotEmpty()) cmd.addAll(listOf("-host", hostOverride))
        return cmd
    }
}
