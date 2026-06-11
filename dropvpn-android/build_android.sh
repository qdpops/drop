#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  build_android.sh
#  Builds drop-client for Android ARM64 as libdrop.so.
#
#  Android 10+ blocks execution from filesDir (W^X policy).
#  Placing the binary in jniLibs/arm64-v8a/ causes Android to
#  extract it to nativeLibraryDir with +x on APK install.
#
#  Usage (from the DROP project root, where dropt/ lives):
#    chmod +x olcrtc-android/build_android.sh
#    ./olcrtc-android/build_android.sh [path/to/olcrtc-android]
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

ANDROID_APP_DIR="${1:-./dropvpn-android}"
JNILIBS_DIR="$ANDROID_APP_DIR/app/src/main/jniLibs/arm64-v8a"

echo "=== DROP Android Build ==="
echo ""

# ── Checks ────────────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
    echo "[ERROR] Go not found. https://go.dev/dl/"
    exit 1
fi
if [ ! -f "dropt/go.mod" ]; then
    echo "[ERROR] Run from the DROP project root (where dropt/ lives)."
    exit 1
fi

echo "[✓] Go: $(go version | awk '{print $3}')"
mkdir -p "$JNILIBS_DIR"

# ── Build drop-client → libdrop.so ───────────────────────────────
echo ""
echo "[*] Building drop-client for android/arm64..."

GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
go build \
    -ldflags="-s -w" \
    -trimpath \
    -o "$JNILIBS_DIR/libdrop.so" \
    ./dropt/cmd/client

echo "[✓] libdrop.so — $(du -sh "$JNILIBS_DIR/libdrop.so" | awk '{print $1}')"

# ── Done ──────────────────────────────────────────────────────────
echo ""
echo "=== jniLibs ready ==="
ls -lh "$JNILIBS_DIR/"

echo ""
echo "Next:"
echo "  cd $ANDROID_APP_DIR && ./gradlew assembleDebug"
echo "  adb install app/build/outputs/apk/debug/app-debug.apk"
echo ""
echo "Deep link format: drop://HOSTNAME/PUBKEY/PSK"
echo "Example:"
echo "  drop://my.cdn.example.ru/0035e92d.../89d576f7..."
