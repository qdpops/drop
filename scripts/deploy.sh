#!/usr/bin/env bash
# deploy.sh — установка DROP-сервера из исходников на Linux
#
# Запуск: sudo bash scripts/deploy.sh [параметры]
# Директория: корень проекта (рядом с dropt/)
#
# Параметры:
#   --domain     DOMAIN    домен сервера для SSL (ставит nginx + Let's Encrypt)
#   --cdn-domain DOMAIN    CDN-домен, к которому подключается приложение (для drop:// ссылки)
#   --email      EMAIL     email для Let's Encrypt (опционально, но рекомендуется)
#   --listen     ADDR      внутренний адрес :порт (по умолчанию :8080)
#   --site       DIR       директория статики для сайта-обложки
#   --regen-keys           перегенерировать ключи даже если конфиг уже есть
#
# Секретный путь для быстрой ссылки генерируется автоматически при первом деплое
# и сохраняется в /etc/drop/config.env для повторных запусков.
#
# Примеры:
#   sudo bash scripts/deploy.sh --domain devdns.ru --cdn-domain my.cdn.example.com \
#                               --email admin@example.com
#   sudo bash scripts/deploy.sh --domain example.com
#   sudo bash scripts/deploy.sh --listen :8080          # без SSL
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── константы ────────────────────────────────────────────────────────────────
INSTALL_DIR=/opt/drop
CONFIG_DIR=/etc/drop
SERVICE=drop
SYSTEM_USER=drop
GO_REQUIRED=1.21
GO_INSTALL_VER=1.22.5

# ── аргументы ────────────────────────────────────────────────────────────────
LISTEN=":8080"
SITE_DIR=""
DOMAIN=""
CDN_DOMAIN=""
EMAIL=""
LINK_PATH=""
REGEN_KEYS=0

while [[ $# -gt 0 ]]; do
  case $1 in
    --domain)      DOMAIN="$2";          shift 2 ;;
    --domain=*)    DOMAIN="${1#*=}";      shift ;;
    --cdn-domain)  CDN_DOMAIN="$2";      shift 2 ;;
    --cdn-domain=*)CDN_DOMAIN="${1#*=}";  shift ;;
    --email)       EMAIL="$2";           shift 2 ;;
    --email=*)     EMAIL="${1#*=}";       shift ;;
    --listen)      LISTEN="$2";          shift 2 ;;
    --listen=*)    LISTEN="${1#*=}";      shift ;;
    --site)        SITE_DIR="$2";        shift 2 ;;
    --site=*)      SITE_DIR="${1#*=}";    shift ;;
    --regen-keys)  REGEN_KEYS=1;         shift ;;
    -h|--help)
      grep '^#' "$0" | head -20 | sed 's/^# \{0,2\}//'
      exit 0
      ;;
    *) echo "Неизвестный параметр: $1" >&2; exit 1 ;;
  esac
done

# ── вспомогательные функции ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}✓${NC}  $*"; }
info() { echo -e "${CYAN}→${NC}  $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
die()  { echo -e "${RED}✗  $*${NC}" >&2; exit 1; }
step() { echo -e "\n${BOLD}── $* ──${NC}"; }

ver_ge() { printf '%s\n%s\n' "$2" "$1" | sort -V -C; }

# ── проверки ─────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Запустите от root: sudo bash scripts/deploy.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
[[ -d "$PROJECT_ROOT/dropt" ]] || \
  die "Директория dropt/ не найдена. Запускайте из корня проекта."

# Если задан домен и listen = :80/:443 — переключаем на :8080 (nginx займёт эти порты)
if [[ -n "$DOMAIN" && ( "$LISTEN" == ":80" || "$LISTEN" == ":443" ) ]]; then
  warn "--domain задан: внутренний порт переключён с $LISTEN на :8080 (nginx займёт 80/443)"
  LISTEN=":8080"
fi

# ── определяем пакетный менеджер ─────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
  PKG_INSTALL="apt-get install -y -q"
  PKG_UPDATE="apt-get update -q"
elif command -v dnf &>/dev/null; then
  PKG_INSTALL="dnf install -y -q"
  PKG_UPDATE="dnf check-update -q; true"
elif command -v yum &>/dev/null; then
  PKG_INSTALL="yum install -y -q"
  PKG_UPDATE="yum check-update -q; true"
else
  PKG_INSTALL=""
  PKG_UPDATE=""
fi

# ── шаг 1: Go ────────────────────────────────────────────────────────────────
step "Go"

# Добавить стандартные пути Go до проверки, чтобы не переустанавливать каждый раз
export PATH="$PATH:/usr/local/go/bin"

need_go_install=0
if command -v go &>/dev/null; then
  CURRENT_GO=$(go version | awk '{print $3}' | tr -d 'go')
  if ver_ge "$CURRENT_GO" "$GO_REQUIRED"; then
    ok "Go $CURRENT_GO уже установлен"
  else
    warn "Go $CURRENT_GO слишком старый (нужен ≥$GO_REQUIRED) — обновляем"
    need_go_install=1
  fi
else
  info "Go не найден — устанавливаем $GO_INSTALL_VER"
  need_go_install=1
fi

if [[ $need_go_install -eq 1 ]]; then
  ARCH=$(uname -m)
  case $ARCH in
    x86_64)  GOARCH=amd64 ;;
    aarch64) GOARCH=arm64 ;;
    armv*)   GOARCH=armv6l ;;
    *)       die "Неизвестная архитектура: $ARCH" ;;
  esac
  TARBALL="go${GO_INSTALL_VER}.linux-${GOARCH}.tar.gz"
  TMP_DIR=$(mktemp -d)
  info "Скачиваем https://go.dev/dl/${TARBALL}"
  curl -fsSL "https://go.dev/dl/${TARBALL}" -o "$TMP_DIR/$TARBALL" \
    || die "Не удалось скачать Go"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$TMP_DIR/$TARBALL"
  rm -rf "$TMP_DIR"
  export PATH="$PATH:/usr/local/go/bin"
  ok "Go $(go version | awk '{print $3}') установлен в /usr/local/go"
fi

export PATH="$PATH:$(go env GOPATH)/bin"

# ── шаг 2: сборка ────────────────────────────────────────────────────────────
step "Сборка бинарей"
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

info "go build ./cmd/server"
(cd "$PROJECT_ROOT/dropt" && \
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
  -o "$BUILD_DIR/drop-server" ./cmd/server)
ok "drop-server готов"

info "go build ./cmd/keygen"
(cd "$PROJECT_ROOT/dropt" && \
  CGO_ENABLED=0 go build -trimpath \
  -o "$BUILD_DIR/keygen" ./cmd/keygen)
ok "keygen готов"

# ── шаг 3: ключи ─────────────────────────────────────────────────────────────
step "Ключи и конфиг"

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"
CONFIG_FILE="$CONFIG_DIR/config.env"

if [[ -f "$CONFIG_FILE" && $REGEN_KEYS -eq 0 ]]; then
  warn "Конфиг $CONFIG_FILE уже существует — ключи сохранены."
  warn "Передайте --regen-keys чтобы перегенерировать."
  # shellcheck source=/dev/null
  source "$CONFIG_FILE"
  STATIC_PRIV="${DROP_STATIC:-}"
  STATIC_PUB="${DROP_PUB:-}"
  PSK="${DROP_PSK:-}"
  [[ -n "$STATIC_PRIV" && -n "$STATIC_PUB" && -n "$PSK" ]] || \
    die "Конфиг повреждён — запустите с --regen-keys"
  ok "Используем существующие ключи"
  # Обновляем изменяемые параметры в конфиге
  sed -i "s|^DROP_LISTEN=.*|DROP_LISTEN=${LISTEN}|" "$CONFIG_FILE"
  ok "DROP_LISTEN обновлён → ${LISTEN}"
  # CDN_DOMAIN: берём из аргумента или из конфига
  if [[ -n "$CDN_DOMAIN" ]]; then
    if grep -q '^DROP_CDN_DOMAIN=' "$CONFIG_FILE"; then
      sed -i "s|^DROP_CDN_DOMAIN=.*|DROP_CDN_DOMAIN=${CDN_DOMAIN}|" "$CONFIG_FILE"
    else
      echo "DROP_CDN_DOMAIN=${CDN_DOMAIN}" >> "$CONFIG_FILE"
    fi
  else
    CDN_DOMAIN="${DROP_CDN_DOMAIN:-}"
  fi
  # LINK_PATH: берём из конфига; если нет — генерируем и дописываем
  LINK_PATH="${DROP_LINK_PATH:-}"
  if [[ -z "$LINK_PATH" ]]; then
    LINK_PATH="/s/$(openssl rand -hex 12)"
    echo "DROP_LINK_PATH=${LINK_PATH}" >> "$CONFIG_FILE"
    ok "Сгенерирован секретный путь: ${LINK_PATH}"
  fi
else
  info "Генерируем ключи..."
  KEYGEN_OUT=$("$BUILD_DIR/keygen")
  STATIC_PRIV=$(awk '/server_static_priv/{print $3}' <<< "$KEYGEN_OUT")
  STATIC_PUB=$(awk '/server_static_pub/{print $3}'   <<< "$KEYGEN_OUT")
  PSK=$(awk '/^psk/{print $3}'                       <<< "$KEYGEN_OUT")

  # Генерируем случайный секретный путь для страницы быстрой ссылки
  LINK_PATH="/s/$(openssl rand -hex 12)"

  cat > "$CONFIG_FILE" <<EOF
# DROP server config
DROP_LISTEN=${LISTEN}
DROP_STATIC=${STATIC_PRIV}
DROP_PUB=${STATIC_PUB}
DROP_PSK=${PSK}
DROP_SITE=${SITE_DIR}
DROP_CDN_DOMAIN=${CDN_DOMAIN}
DROP_LINK_PATH=${LINK_PATH}
EOF
  chmod 600 "$CONFIG_FILE"
  ok "Ключи сохранены в $CONFIG_FILE"
fi

# ── шаг 4: установка бинаря ──────────────────────────────────────────────────
step "Установка"

if ! id "$SYSTEM_USER" &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SYSTEM_USER"
  ok "Создан пользователь $SYSTEM_USER"
fi

mkdir -p "$INSTALL_DIR"
chown "$SYSTEM_USER:$SYSTEM_USER" "$INSTALL_DIR"

if [[ -f "$INSTALL_DIR/drop-server" ]]; then
  cp "$INSTALL_DIR/drop-server" "$INSTALL_DIR/drop-server.bak"
  info "Резервная копия: $INSTALL_DIR/drop-server.bak"
fi

install -m 0755 -o root -g root "$BUILD_DIR/drop-server" "$INSTALL_DIR/drop-server"
chown root:root "$CONFIG_DIR"
chmod 755 "$CONFIG_DIR"
chown root:"$SYSTEM_USER" "$CONFIG_FILE"
chmod 640 "$CONFIG_FILE"
ok "Бинарь установлен в $INSTALL_DIR/drop-server"

# ── шаг 5: systemd ───────────────────────────────────────────────────────────
step "systemd unit"

EXEC_START="$INSTALL_DIR/drop-server -listen \${DROP_LISTEN} -static \${DROP_STATIC} -psk \${DROP_PSK}"
[[ -n "$SITE_DIR" ]] && EXEC_START="$EXEC_START -site \${DROP_SITE}"
# link-host — CDN-домен (к нему подключается приложение, он же идёт в drop:// ссылку)
if [[ -n "$LINK_PATH" && -n "$CDN_DOMAIN" ]]; then
  EXEC_START="$EXEC_START -link-host \${DROP_CDN_DOMAIN} -link-path \${DROP_LINK_PATH}"
fi

cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=DROP covert transport server
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=${SYSTEM_USER}
EnvironmentFile=${CONFIG_FILE}
ExecStart=${EXEC_START}
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE"
ok "Сервис ${SERVICE}.service зарегистрирован"

# ── шаг 6: запуск DROP-сервера ───────────────────────────────────────────────
step "Запуск DROP-сервера"

if systemctl is-active --quiet "$SERVICE"; then
  info "Перезапускаем работающий сервис..."
  systemctl restart "$SERVICE"
else
  systemctl start "$SERVICE"
fi

sleep 1
systemctl is-active --quiet "$SERVICE" \
  || die "Сервис не запустился. Лог: journalctl -u $SERVICE -n 30"
ok "DROP-сервер запущен на $LISTEN"

# ── шаг 7: nginx + Let's Encrypt ─────────────────────────────────────────────
if [[ -n "$DOMAIN" ]]; then
  step "nginx + Let's Encrypt (${DOMAIN})"

  [[ -n "$PKG_INSTALL" ]] || die "Не найден поддерживаемый пакетный менеджер (apt/dnf/yum)"

  INTERNAL_PORT="${LISTEN#:}"

  # ── 7a: установка nginx ───────────────────────────────────────────────────
  if ! command -v nginx &>/dev/null; then
    info "Устанавливаем nginx..."
    eval "$PKG_UPDATE"
    eval "$PKG_INSTALL nginx"
    ok "nginx установлен"
  else
    ok "nginx $(nginx -v 2>&1 | grep -oP '[\d.]+' | head -1) уже установлен"
  fi

  # ── 7b: установка certbot ─────────────────────────────────────────────────
  if ! command -v certbot &>/dev/null; then
    info "Устанавливаем certbot..."
    if command -v apt-get &>/dev/null; then
      eval "$PKG_INSTALL certbot python3-certbot-nginx"
    elif command -v dnf &>/dev/null; then
      eval "$PKG_INSTALL certbot python3-certbot-nginx"
    else
      # RHEL/CentOS — certbot через pip как запасной вариант
      eval "$PKG_INSTALL python3-pip"
      pip3 install -q certbot certbot-nginx
    fi
    ok "certbot установлен"
  else
    ok "certbot $(certbot --version 2>&1 | awk '{print $2}') уже установлен"
  fi

  # ── 7c: освободить порты 80/443 ──────────────────────────────────────────
  # Сначала остановить DROP — он мог запуститься на :80 по старому конфигу.
  # После того как nginx поднимется, DROP будет запущен на $LISTEN (:8080).
  if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    info "Останавливаем $SERVICE (освобождаем порт для nginx)..."
    systemctl stop "$SERVICE"
    ok "$SERVICE остановлен"
  fi

  # Apache2 установлен по умолчанию на Ubuntu/Debian и занимает :80
  if systemctl is-active --quiet apache2 2>/dev/null; then
    warn "Apache2 занимает порт 80 — останавливаем и отключаем"
    systemctl stop apache2
    systemctl disable apache2
    ok "Apache2 остановлен"
  fi

  # Любые оставшиеся процессы на портах 80 и 443
  for PORT in 80 443; do
    PIDS=$(ss -tlnp "sport = :${PORT}" 2>/dev/null \
           | grep -oP 'pid=\K\d+' | sort -u || true)
    for PID in $PIDS; do
      PNAME=$(cat "/proc/${PID}/comm" 2>/dev/null || echo "pid:${PID}")
      if [[ "$PNAME" != "nginx" ]]; then
        warn "Порт ${PORT} занят процессом ${PNAME} (PID ${PID}) — завершаем"
        kill -TERM "$PID" 2>/dev/null || true
      fi
    done
  done
  sleep 1

  # ── 7d: HTTP-конфиг nginx (нужен для ACME challenge) ─────────────────────
  NGINX_CONF="/etc/nginx/sites-available/drop"
  NGINX_ENABLED="/etc/nginx/sites-enabled/drop"

  # Отключить дефолтный сайт если он занимает :80
  [[ -f /etc/nginx/sites-enabled/default ]] && rm -f /etc/nginx/sites-enabled/default

  cat > "$NGINX_CONF" <<NGINXEOF
server {
    listen 80;
    server_name ${DOMAIN};

    # ACME challenge (certbot)
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location /api/ {
        proxy_pass         http://127.0.0.1:${INTERNAL_PORT}/api/;
        proxy_http_version 1.1;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_read_timeout 60s;
        proxy_buffering    off;
    }

    location / {
        proxy_pass         http://127.0.0.1:${INTERNAL_PORT}/;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
    }
}
NGINXEOF

  ln -sf "$NGINX_CONF" "$NGINX_ENABLED"
  mkdir -p /var/www/certbot

  nginx -t || die "nginx конфиг некорректен — проверьте $NGINX_CONF"
  systemctl enable nginx
  systemctl restart nginx
  ok "nginx запущен (HTTP :80)"

  # ── 7e: получение сертификата ─────────────────────────────────────────────
  info "Запрашиваем сертификат Let's Encrypt..."

  CERTBOT_FLAGS="--nginx -d ${DOMAIN} --non-interactive --agree-tos"
  if [[ -n "$EMAIL" ]]; then
    CERTBOT_FLAGS="$CERTBOT_FLAGS --email ${EMAIL}"
  else
    warn "Email не указан (--email). Используем --register-unsafely-without-email."
    warn "Укажите email чтобы получать уведомления об истечении сертификата."
    CERTBOT_FLAGS="$CERTBOT_FLAGS --register-unsafely-without-email"
  fi

  # shellcheck disable=SC2086
  certbot $CERTBOT_FLAGS \
    || die "certbot завершился с ошибкой.
  Убедитесь что:
    1. DNS домена ${DOMAIN} указывает на этот сервер
    2. Порт 80 открыт в firewall
    3. Нет другого сервиса на порту 80"

  ok "SSL сертификат получен: /etc/letsencrypt/live/${DOMAIN}/"

  # certbot --nginx сам перезаписывает конфиг и добавляет SSL.
  # Добавляем оптимизированные заголовки и проксирование поверх того что certbot написал.
  # Перезаписываем конфиг полностью — с SSL уже в виде готового файла.
  cat > "$NGINX_CONF" <<NGINXEOF
# HTTP → HTTPS редирект
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}

# HTTPS терминация + прокси на DROP
server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;

    # OCSP stapling
    ssl_stapling        on;
    ssl_stapling_verify on;
    resolver            1.1.1.1 8.8.8.8 valid=300s;

    # Проксирование на DROP-сервер
    location /api/ {
        proxy_pass         http://127.0.0.1:${INTERNAL_PORT}/api/;
        proxy_http_version 1.1;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 65s;
        proxy_buffering    off;
        proxy_cache        off;
    }

    location / {
        proxy_pass         http://127.0.0.1:${INTERNAL_PORT}/;
        proxy_http_version 1.1;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
    }
}
NGINXEOF

  nginx -t || die "итоговый nginx конфиг некорректен"
  systemctl reload nginx
  ok "nginx перезагружен с SSL"

  # Запустить DROP на внутреннем порту (был остановлен в 7c)
  systemctl start "$SERVICE"
  sleep 1
  systemctl is-active --quiet "$SERVICE" \
    || die "DROP не запустился после nginx. Лог: journalctl -u $SERVICE -n 30"
  ok "$SERVICE запущен на ${LISTEN}"

  # ── 7f: авто-обновление сертификата ──────────────────────────────────────
  # certbot при установке через apt обычно добавляет systemd timer автоматически.
  # Проверяем и добавляем cron как запасной вариант.
  if systemctl list-timers --all 2>/dev/null | grep -q certbot; then
    ok "Авто-обновление: certbot.timer активен (systemd)"
  elif crontab -l 2>/dev/null | grep -q certbot; then
    ok "Авто-обновление: уже есть в cron"
  else
    (crontab -l 2>/dev/null; \
     echo "0 3 * * * certbot renew --quiet --deploy-hook 'systemctl reload nginx'") \
     | crontab -
    ok "Авто-обновление: добавлен cron (каждый день в 03:00)"
  fi
fi

# ── итог ─────────────────────────────────────────────────────────────────────
SERVER_IP=$(curl -fsSL --max-time 3 https://api.ipify.org 2>/dev/null \
            || hostname -I | awk '{print $1}')

if [[ -n "$DOMAIN" ]]; then
  CLIENT_URL="https://${DOMAIN}/"
else
  CLIENT_URL="http://${SERVER_IP}${LISTEN}/"
fi

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║           DROP сервер развёрнут успешно                     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Команда запуска клиента:${NC}"
echo ""
echo "  drop-client \\"
echo "    -url  ${CLIENT_URL} \\"
echo "    -pub  ${STATIC_PUB} \\"
echo "    -psk  ${PSK} \\"
echo "    -socks 127.0.0.1:1080"
echo ""
if [[ -n "$DOMAIN" ]]; then
  echo -e "${GREEN}SSL активен:${NC} https://${DOMAIN}/"
  echo -e "${YELLOW}Сертификат: /etc/letsencrypt/live/${DOMAIN}/fullchain.pem${NC}"
fi
if [[ -n "$LINK_PATH" && -n "$CDN_DOMAIN" ]]; then
  echo ""
  echo -e "${BOLD}Быстрая ссылка для Android-приложения:${NC}"
  echo -e "  ${GREEN}https://${CDN_DOMAIN}${LINK_PATH}${NC}"
  echo -e "  ${CYAN}drop://${CDN_DOMAIN}/${STATIC_PUB}/${PSK}${NC}"
fi
echo ""
echo -e "${YELLOW}Лог DROP:   journalctl -u ${SERVICE} -f${NC}"
echo -e "${YELLOW}Лог nginx:  tail -f /var/log/nginx/error.log${NC}"
echo ""
