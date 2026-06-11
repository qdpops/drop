# olcRTC ProGuard rules

# Keep the service and receiver
-keep class xyz.olcrtc.android.TunnelService { *; }
-keep class xyz.olcrtc.android.BootReceiver { *; }
-keep class xyz.olcrtc.android.BinaryManager { *; }

# Keep Kotlin coroutines
-keepnames class kotlinx.coroutines.** { *; }
-keep class kotlinx.coroutines.android.** { *; }

# Keep AndroidX lifecycle
-keep class androidx.lifecycle.** { *; }
