# DROP VPN

A covert HTTPS/CDN transport that tunnels traffic through any CDN-fronted domain. The server masquerades as an ordinary website; the hidden channel rides inside two plausible-looking API endpoints. By design, an active prober cannot distinguish the host from a real web service.

```
Android app ──SOCKS5──► drop-client ──HTTPS POST/GET──► CDN ──► drop-server ──► Internet
```

---

## Architecture

### Protocol

The channel is split into two HTTP endpoints:

| Endpoint | Direction | Disguise |
|---|---|---|
| `POST /api/events` | client → server (upstream) | looks like telemetry |
| `GET  /api/updates` | server → client (downstream) | long-poll "sync" |

Requests that fail authentication under the PSK receive ordinary website responses — the server is indistinguishable from a real site to anyone without the key (**probe resistance**).

### Cryptography

- **Handshake**: Noise_N-style. The server holds a long-term X25519 static key. The client generates a fresh ephemeral X25519 key per session and performs ECDH against the server static key.
- **Key derivation**: `HKDF(ECDH_shared, PSK)` → two AES-256-GCM keys (c→s and s→c).
- **PSK role**: folded into HKDF as salt. Without the PSK the AEAD open fails, so unauthenticated probers get the decoy site.
- **Framing**: `stream(4) | type(1) | len(2) | payload` — many SOCKS connections multiplexed over one HTTP channel.
- **Windowing**: `windowSize=8` parallel POST lanes + 8 concurrent long-poll GETs, with a downstream reorder buffer ensuring in-order delivery.

### Android VPN

```
All apps → TUN fd (VpnService)
           → TunPacketForwarder  [in-process, same SELinux context]
           → SOCKS5 127.0.0.1:8808
           → libdrop.so subprocess (excluded from VPN via addDisallowedApplication)
           → DROP tunnel → Internet
```

**Why in-process forwarder instead of tun2socks**: Android SELinux blocks `ioctl(TUNGETIFF)` in child processes even with an inherited fd. Running the forwarder in the VpnService process uses its SELinux context and works without root.

**DNS on restrictive operators**: Before creating the TUN interface, `OlcVpnService` reads the active network's `LinkProperties.dnsServers()` (operator-assigned DNS). This DNS is passed to `libdrop.so` via `-dns` and used in `TunPacketForwarder.forwardDns()` via a `protect()`-ed socket. This fixes DNS interception on operators like Megafon that block direct access to `8.8.8.8:53`.

**TCP ordering**: All TUN→SOCKS5 writes go through a per-connection `Channel<ByteArray>(UNLIMITED)` with a single writer coroutine, preventing `ERR_SSL_BAD_RECORD_MAC_ALERT` caused by out-of-order socket writes.

---

## Project Structure

```
DROP/
├── dropt/                          Go source — zero external dependencies
│   ├── cmd/server/main.go          HTTP covert transport server
│   ├── cmd/client/main.go          SOCKS5 → DROP tunnel client (→ libdrop.so)
│   ├── cmd/keygen/main.go          Key generation utility
│   └── internal/wire/wire.go       Framing + AES-256-GCM + HKDF cryptography
│
├── dropvpn-android/                 Android VPN app (Kotlin, minSdk 26)
│   ├── app/src/main/java/xyz/olcrtc/android/
│   │   ├── MainActivity.kt         UI, deep-link handler (drop://)
│   │   ├── OlcVpnService.kt        VPN mode: TUN + TunPacketForwarder
│   │   ├── TunnelService.kt        SOCKS5-only mode (no VPN)
│   │   ├── TunPacketForwarder.kt   Raw IP → SOCKS5 forwarder + DNS relay
│   │   ├── BinaryManager.kt        Manages libdrop.so subprocess
│   │   ├── Prefs.kt                SharedPreferences helper
│   │   └── BootReceiver.kt         Auto-start on boot
│   ├── app/src/main/jniLibs/arm64-v8a/libdrop.so   Compiled drop-client binary
│   └── build_android.sh            Rebuilds libdrop.so from source
│
└── scripts/
    └── deploy.sh                   One-command server deployment (Linux)
```

---

## Server Deployment

### Requirements

- Linux server (amd64 or arm64), Ubuntu/Debian/CentOS/RHEL
- Publicly accessible IP with DNS record pointing to it
- Port 80 and 443 open (for Let's Encrypt + nginx)
- A CDN service fronting your domain (Cloudflare, etc.)

### Deploy

```bash
git clone https://github.com/qdpops/drop.git
cd drop

sudo bash scripts/deploy.sh \
  --domain    your-origin.example.com \
  --cdn-domain your-cdn.example.com \
  --email     admin@example.com
```

The script does everything automatically:

1. Installs Go ≥ 1.21 if missing
2. Builds `drop-server` and `drop-keygen` from source
3. Generates X25519 static key + PSK, saves to `/etc/drop/config.env`
4. Generates a secret random path (e.g. `/s/a3f8c1...`) for the Android quick-link page
5. Installs the binary to `/opt/drop/drop-server`
6. Creates and enables a `systemd` service (`drop.service`) running as a dedicated user
7. Installs nginx + Certbot, obtains a Let's Encrypt TLS certificate
8. Configures nginx as HTTPS terminator + reverse proxy with `proxy_buffering off` on `/api/`
9. Sets up automatic certificate renewal

After deployment the output shows:

```
Команда запуска клиента:
  drop-client -url https://your-cdn.example.com/ -pub <PUB> -psk <PSK> -socks 127.0.0.1:1080

Быстрая ссылка для Android-приложения:
  https://your-cdn.example.com/s/a3f8c1...
  drop://your-cdn.example.com/<PUB>/<PSK>
```

### CDN Configuration

For the transport to work through a CDN, configure the following rules on the CDN side:

| Rule | Setting |
|---|---|
| `/api/*` | **Cache: bypass** (never cache) |
| `/api/updates` | **Response buffering: off** (or increase timeout to ≥ 60 s) |
| **Origin read timeout** | ≥ 60 s (server holds long-poll for 15 s + slack) |
| **Origin write timeout** | ≥ 35 s |

The rest of the site (`/`) can be cached normally — this is intentional for the camouflage.

### Manual Server Flags

```
drop-server [flags]

  -listen    string   listen address (default ":8080")
  -static    string   server static private key hex (from keygen)
  -psk       string   pre-shared key hex (from keygen)
  -site      string   directory of real static files to serve as the decoy site
  -link-host string   public CDN hostname for drop:// links
  -link-path string   secret URL path for the Android quick-link page
```

### Key Generation

```bash
cd dropt
go run ./cmd/keygen

# server_static_priv = <hex>   ← keep on server only
# server_static_pub  = <hex>   ← ship to clients
# psk                = <hex>   ← both sides
```

---

## Android App

### Build `libdrop.so`

The Android app runs `drop-client` as a subprocess (`libdrop.so` in `nativeLibraryDir`). Rebuild it whenever the Go client code changes:

```bash
# From the project root (where dropt/ lives):
./dropvpn-android/build_android.sh
```

Or manually:

```bash
cd dropt
GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
  go build -ldflags="-s -w" -trimpath \
  -o ../dropvpn-android/app/src/main/jniLibs/arm64-v8a/libdrop.so \
  ./cmd/client
```

### Build APK

Open `dropvpn-android/` in **Android Studio** (Electric Eel or newer) and choose:
- **Build → Generate Signed Bundle/APK** for release
- **Run** button for debug install on a connected device

Or via Gradle:

```bash
cd dropvpn-android
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

Requirements: Android 8.0+ (API 26), ARM64 device.

### Connect via Quick Link

After server deployment, open the quick-link URL in a browser on your Android device:

```
https://your-cdn.example.com/s/<secret>
```

Tap **"Открыть в приложении"** — the app will parse the `drop://` deep link and pre-fill all settings automatically.

### Manual Configuration

| Field | Value |
|---|---|
| Server URL | `https://your-cdn.example.com/` |
| Public key | `<server_static_pub>` hex from keygen |
| PSK | `<psk>` hex from keygen |
| SOCKS port | `8808` (default) |

### Deep Link Format

```
drop://HOSTNAME/PUB_HEX/PSK_HEX
```

Example:
```
drop://cdn.example.com/0035e92d4a8b.../89d576f7c3a1...
```

### App Modes

| Mode | Description |
|---|---|
| **VPN mode** | All device traffic tunneled. Uses `VpnService` TUN interface + in-process `TunPacketForwarder`. |
| **SOCKS5 mode** | Local `127.0.0.1:8808` proxy only. Configure manually in browser or use a proxy app. |

---

## Building Server from Source

```bash
cd dropt

# Server
go build -o drop-server ./cmd/server

# Client (Linux/macOS/Windows)
go build -o drop-client ./cmd/client

# Key generator
go build -o drop-keygen ./cmd/keygen
```

Zero external dependencies — stdlib only. Binaries are self-contained.

---

## Service Management

```bash
# Status
systemctl status drop

# Logs (live)
journalctl -u drop -f

# Restart
systemctl restart drop

# nginx logs
tail -f /var/log/nginx/error.log
```

Config file: `/etc/drop/config.env`
Binary: `/opt/drop/drop-server`

---

## Security Notes

- The **PSK** and **server_static_priv** must be kept secret. Anyone with the PSK can connect.
- **No forward secrecy** in the current version: compromise of `server_static_priv` exposes past sessions. Upgrading to a full Noise_XX handshake is the next planned step.
- The quick-link URL at `/s/<random>` contains the PSK in the `drop://` URI — use HTTPS only and do not share the link publicly.
- One quick-link URL can be shared with multiple users; all users share the same PSK.
