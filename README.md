# DROP VPN

Скрытый VPN-транспорт поверх HTTPS/CDN. Сервер выглядит как обычный сайт — канал спрятан внутри двух правдоподобных API-эндпоинтов. Активный зонд не может отличить хост от настоящего веб-сервиса.

```
Android-приложение ──SOCKS5──► drop-client ──HTTPS POST/GET──► CDN ──► drop-server ──► Интернет
```

---

## Архитектура

### Протокол

Канал разделён на два HTTP-эндпоинта:

| Эндпоинт | Направление | Камуфляж |
|---|---|---|
| `POST /api/events` | клиент → сервер (upstream) | выглядит как телеметрия |
| `GET  /api/updates` | сервер → клиент (downstream) | long-poll «синхронизация» |

Запросы, не прошедшие аутентификацию под PSK, получают обычные ответы сайта — **probe resistance**: сервер неотличим от настоящего хоста без знания ключей.

### Криптография

- **Рукопожатие**: стиль Noise_N. Сервер хранит долгосрочный X25519-ключ. Клиент генерирует эфемерный X25519-ключ на каждую сессию и выполняет ECDH с публичным ключом сервера.
- **Derivation ключей**: `HKDF(ECDH_shared, PSK)` → два ключа AES-256-GCM (c→s и s→c).
- **Роль PSK**: подмешивается в HKDF как соль. Без PSK AEAD-open завершается ошибкой — зонд получает страницу-приманку.
- **Фреймирование**: `stream(4) | type(1) | len(2) | payload` — множество SOCKS-соединений мультиплексируется по одному HTTP-каналу.
- **Оконный слой**: 8 параллельных POST-полос + 8 параллельных long-poll GET с reorder-буфером, гарантирующим доставку в исходном порядке.

### Android VPN

```
Все приложения → TUN fd (VpnService)
                 → TunPacketForwarder  [в процессе, тот же SELinux-контекст]
                 → SOCKS5 127.0.0.1:8808
                 → subprocess libdrop.so (исключён из VPN через addDisallowedApplication)
                 → DROP-туннель → Интернет
```

**Почему форвардер в процессе, а не tun2socks-процесс**: Android SELinux блокирует `ioctl(TUNGETIFF)` в дочерних процессах даже при корректно переданном fd. Форвардер внутри VpnService использует его SELinux-контекст — работает без root.

**DNS на блокирующих операторах**: перед созданием TUN-интерфейса `OlcVpnService` читает `LinkProperties.dnsServers()` активной сети (DNS, выданный оператором). Этот DNS передаётся в `libdrop.so` через флаг `-dns` и используется в `TunPacketForwarder.forwardDns()` через `protect()`-сокет. Фикс для некоторых Российских операторов, блокирующих прямой доступ к `8.8.8.8:53`.

**Порядок TCP**: все записи TUN→SOCKS5 проходят через `Channel<ByteArray>(UNLIMITED)` на соединение с единственным writer-корутином — предотвращает `ERR_SSL_BAD_RECORD_MAC_ALERT` из-за out-of-order записей в сокет.

---

## Структура проекта

```
DROP/
├── dropt/                          Go-исходники, ноль внешних зависимостей
│   ├── cmd/server/main.go          HTTP-сервер скрытого транспорта
│   ├── cmd/client/main.go          SOCKS5 → DROP-туннель клиент (→ libdrop.so)
│   ├── cmd/keygen/main.go          Генератор ключей
│   └── internal/wire/wire.go       Фреймирование + AES-256-GCM + HKDF
│
├── dropvpn-android/                Android VPN-приложение (Kotlin, minSdk 26)
│   ├── app/src/main/java/xyz/olcrtc/android/
│   │   ├── MainActivity.kt         UI, обработка deep-link (drop://)
│   │   ├── OlcVpnService.kt        VPN-режим: TUN + TunPacketForwarder
│   │   ├── TunnelService.kt        Режим SOCKS5-прокси (без VPN)
│   │   ├── TunPacketForwarder.kt   Сырые IP-пакеты → SOCKS5 + DNS-relay
│   │   ├── BinaryManager.kt        Управление subprocess libdrop.so
│   │   ├── Prefs.kt                SharedPreferences-хелпер
│   │   └── BootReceiver.kt         Автозапуск при загрузке
│   ├── app/src/main/jniLibs/arm64-v8a/libdrop.so   Скомпилированный drop-client
│   └── build_android.sh            Пересборка libdrop.so из исходников
│
└── scripts/
    └── deploy.sh                   Одна команда для развёртывания на Linux
```

---

## Развёртывание сервера

### Требования

- Linux-сервер (amd64 или arm64): Ubuntu, Debian, CentOS, RHEL
- Публичный IP, DNS-запись домена указывает на сервер
- Открытые порты 80 и 443
- CDN-сервис, проксирующий ваш домен (VK Cloud и др.)

### Запуск

```bash
git clone https://github.com/qdpops/drop.git
cd drop

sudo bash scripts/deploy.sh \
  --domain    ваш-сервер.example.com \
  --cdn-domain ваш-cdn.example.com \
  --email     admin@example.com
```

Скрипт выполняет всё автоматически:

1. Устанавливает Go ≥ 1.21, если не установлен
2. Компилирует `drop-server` и `drop-keygen` из исходников
3. Генерирует X25519 static key + PSK, сохраняет в `/etc/drop/config.env`
4. Генерирует секретный случайный путь (например `/s/a3f8c1...`) для страницы быстрой ссылки
5. Устанавливает бинарь в `/opt/drop/drop-server`
6. Создаёт и включает `systemd`-сервис (`drop.service`) от отдельного пользователя
7. Устанавливает nginx + Certbot, получает TLS-сертификат Let's Encrypt
8. Настраивает nginx как HTTPS-терминатор + reverse proxy с `proxy_buffering off` на `/api/`
9. Настраивает автоматическое обновление сертификата

После развёртывания скрипт выводит:

```
Команда запуска клиента:
  drop-client -url https://ваш-cdn.example.com/ -pub <PUB> -psk <PSK> -socks 127.0.0.1:1080

Быстрая ссылка для Android-приложения:
  https://ваш-cdn.example.com/s/a3f8c1...
  drop://ваш-cdn.example.com/<PUB>/<PSK>
```

### Настройка CDN

| Правило | Настройка |
|---|---|
| `/api/*` | **Cache: bypass** — никогда не кэшировать |
| `/api/updates` | **Буферизация ответа: выкл** (или таймаут ≥ 60 с) |
| **Origin read timeout** | ≥ 60 с (сервер держит long-poll 15 с + запас) |
| **Origin write timeout** | ≥ 35 с |

Остальной сайт (`/`) можно кэшировать — это намеренно, для камуфляжа.

### Флаги сервера вручную

```
drop-server [флаги]

  -listen    string   адрес прослушивания (по умолчанию ":8080")
  -static    string   приватный X25519-ключ сервера в hex (из keygen)
  -psk       string   pre-shared key в hex (из keygen)
  -site      string   директория статики для сайта-приманки
  -link-host string   публичный CDN-домен для drop://-ссылок
  -link-path string   секретный URL-путь страницы быстрой ссылки
```

### Генерация ключей

```bash
cd dropt
go run ./cmd/keygen

# server_static_priv = <hex>   ← только на сервере
# server_static_pub  = <hex>   ← передать клиентам
# psk                = <hex>   ← обе стороны
```

---

## Android-приложение

### Сборка `libdrop.so`

Приложение запускает `drop-client` как subprocess (`libdrop.so` в `nativeLibraryDir`). Пересобирайте при изменениях в Go-клиенте:

```bash
# Из корня проекта (где лежит dropt/):
./dropvpn-android/build_android.sh
```

Или вручную:

```bash
cd dropt
GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
  go build -ldflags="-s -w" -trimpath \
  -o ../dropvpn-android/app/src/main/jniLibs/arm64-v8a/libdrop.so \
  ./cmd/client
```

### Сборка APK

Откройте `dropvpn-android/` в **Android Studio** (Electric Eel или новее):
- **Build → Generate Signed Bundle/APK** — для release
- Кнопка **Run** — для debug-установки на подключённое устройство

Или через Gradle:

```bash
cd dropvpn-android
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

Требования: Android 8.0+ (API 26), устройство ARM64.

### Подключение через быструю ссылку

После развёртывания откройте URL быстрой ссылки в браузере на Android-устройстве:

```
https://ваш-cdn.example.com/s/<секрет>
```

Нажмите **«Открыть в приложении»** — приложение разберёт `drop://` deep link и заполнит все настройки автоматически.

### Ручная настройка

| Поле | Значение |
|---|---|
| Server URL | `https://ваш-cdn.example.com/` |
| Public key | `<server_static_pub>` hex из keygen |
| PSK | `<psk>` hex из keygen |
| SOCKS port | `8808` (по умолчанию) |

### Формат deep link

```
drop://HOSTNAME/PUB_HEX/PSK_HEX
```

### Режимы работы

| Режим | Описание |
|---|---|
| **VPN-режим** | Весь трафик устройства через туннель. Использует `VpnService`, TUN-интерфейс и `TunPacketForwarder` в процессе. |
| **SOCKS5-режим** | Только локальный прокси `127.0.0.1:8808`. Настраивается вручную в браузере или через proxy-приложение. |

---

## Сборка сервера из исходников

```bash
cd dropt

go build -o drop-server  ./cmd/server
go build -o drop-client  ./cmd/client
go build -o drop-keygen  ./cmd/keygen
```

Внешних зависимостей нет — только стандартная библиотека Go. Бинарники самодостаточны.

---

## Управление сервисом

```bash
# Статус
systemctl status drop

# Логи (live)
journalctl -u drop -f

# Перезапуск
systemctl restart drop

# Логи nginx
tail -f /var/log/nginx/error.log
```

Конфиг: `/etc/drop/config.env`  
Бинарь: `/opt/drop/drop-server`

---

## Безопасность

- **PSK** и **server_static_priv** должны оставаться секретными — любой владелец PSK может подключиться.
- **Нет forward secrecy** в текущей версии: компрометация `server_static_priv` раскрывает прошлые сессии. Переход на полный Noise_XX — следующий запланированный шаг.
- URL быстрой ссылки `/s/<random>` содержит PSK в `drop://`-URI — используйте только через HTTPS, не публикуйте ссылку открыто.
- Одну быструю ссылку можно раздать нескольким пользователям — все подключаются с одним PSK.
