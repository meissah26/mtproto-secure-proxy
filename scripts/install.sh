#!/bin/bash
set -euo pipefail

# ============================================================
#  MTProto Secure Proxy — One-Click Installer
#  Deploys: mtg v2 (FakeTLS) + masquerade site + monitoring
#
#  Usage:
#    sudo ./install.sh
#
#  Environment variables (optional):
#    CLOAK_DOMAIN  — FakeTLS domain (default: www.microsoft.com)
#    SERVER_IP     — override auto-detected public IP
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1" >&2; }

INSTALL_DIR="/opt/mtproto-proxy"
CLOAK_DOMAIN="${CLOAK_DOMAIN:-www.microsoft.com}"

# ── Pre-checks ──────────────────────────────────────────────
[ "$EUID" -ne 0 ] && { err "Run as root: sudo $0"; exit 1; }

log "MTProto Secure Proxy — Installer"
echo "─────────────────────────────────"

# ── Docker ──────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  log "Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
fi

if ! docker compose version &>/dev/null 2>&1; then
  log "Installing Docker Compose plugin..."
  mkdir -p /usr/local/lib/docker/cli-plugins
  ARCH=$(uname -m)
  curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${ARCH}" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose 2>/dev/null
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
fi
log "Docker $(docker --version | grep -oP '\d+\.\d+\.\d+')"

# ── Swap (prevent OOM on small VPS) ────────────────────────
if [ ! -f /swapfile ]; then
  log "Creating 2 GB swap..."
  fallocate -l 2G /swapfile && chmod 600 /swapfile
  mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# ── Copy project files ─────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
if [ "${SCRIPT_DIR}" != "${INSTALL_DIR}" ]; then
  log "Copying project to ${INSTALL_DIR}..."
  mkdir -p "${INSTALL_DIR}"
  rsync -a --exclude='.git' "${SCRIPT_DIR}/" "${INSTALL_DIR}/"
fi
cd "${INSTALL_DIR}"

# ── Generate secrets ───────────────────────────────────────
log "Pulling mtg image..."
docker pull nineseconds/mtg:2 2>&1 | tail -2

log "Generating FakeTLS secret (cloak: ${CLOAK_DOMAIN})..."
MTG_SECRET=$(docker run --rm nineseconds/mtg:2 generate-secret "${CLOAK_DOMAIN}")
DASHBOARD_SECRET=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)

log "Secret generated"

# ── mtg config ─────────────────────────────────────────────
cat > mtg-config.toml <<EOF
secret = "${MTG_SECRET}"
bind-to = "0.0.0.0:443"
concurrency = 8192
prefer-ip = "prefer-ipv6"

[domain-fronting]
port = 8444
ip = "10.77.0.10"

[stats.prometheus]
enabled = true
bind-to = "0.0.0.0:3129"
http-path = "/"
metric-prefix = "mtg"

[defense.anti-replay]
enabled = true
max-size = "128MB"
EOF

# ── .env ───────────────────────────────────────────────────
cat > .env <<EOF
DASHBOARD_SECRET=${DASHBOARD_SECRET}
EOF
chmod 600 .env

# ── TLS certificate (self-signed, for cloak nginx) ────────
log "Generating TLS certificate..."
mkdir -p nginx/certs
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout nginx/certs/server.key -out nginx/certs/server.crt \
  -subj "/C=NL/ST=Noord-Holland/L=Amsterdam/O=Web Services/CN=web.local" \
  -addext "subjectAltName=DNS:web.local" 2>/dev/null
chmod 600 nginx/certs/server.key

# ── SSH key pair ───────────────────────────────────────────
log "Generating SSH key pair..."
mkdir -p keys
ssh-keygen -t ed25519 -f keys/mtproxy_ed25519 -N "" -C "mtproxy-access" 2>/dev/null
mkdir -p /root/.ssh
grep -qF "mtproxy-access" /root/.ssh/authorized_keys 2>/dev/null || \
  cat keys/mtproxy_ed25519.pub >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# ── Firewall ───────────────────────────────────────────────
log "Configuring firewall..."
apt-get install -y -qq ufw 2>/dev/null || true
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp   >/dev/null  # SSH
ufw allow 443/tcp  >/dev/null  # MTProto + cloak
ufw allow 9090/tcp >/dev/null  # Monitoring dashboard
ufw --force enable >/dev/null
log "Firewall: 22, 443, 9090 open"

# ── Kernel hardening ───────────────────────────────────────
cat > /etc/sysctl.d/99-mtproxy.conf <<'SYSEOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
SYSEOF
sysctl -p /etc/sysctl.d/99-mtproxy.conf >/dev/null 2>&1 || true

# ── Build & Start ──────────────────────────────────────────
log "Building monitoring image..."
docker compose build monitoring 2>&1 | tail -3

log "Starting all services..."
docker compose up -d 2>&1 | grep -v "^$"

log "Waiting for services..."
sleep 10

# ── Verify ─────────────────────────────────────────────────
ERRORS=0
for svc in mtg nginx monitoring; do
  if docker compose ps 2>/dev/null | grep -q "${svc}.*Up"; then
    log "✓ ${svc}"
  else
    err "✗ ${svc} not running"
    docker compose logs --tail 5 "${svc}" 2>&1
    ERRORS=$((ERRORS+1))
  fi
done

# ── Connection info ────────────────────────────────────────
SERVER_IP="${SERVER_IP:-$(curl -s -4 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')}"

MTG_HEX=$(python3 -c "
import base64
s='${MTG_SECRET}'.replace('-','+').replace('_','/')
s+='='*(4-len(s)%4)
print(base64.b64decode(s).hex())
" 2>/dev/null)

TG_LINK="tg://proxy?server=${SERVER_IP}&port=443&secret=${MTG_HEX}"
TG_HTTPS="https://t.me/proxy?server=${SERVER_IP}&port=443&secret=${MTG_HEX}"
DASH_URL="http://${SERVER_IP}:9090/dashboard/${DASHBOARD_SECRET}"

# ── Save connection info ───────────────────────────────────
cat > CONNECTION_INFO.txt <<INFOEOF
═══════════════════════════════════════════
  MTProto Secure Proxy — Connection Info
═══════════════════════════════════════════

Server:       ${SERVER_IP}
Port:         443
FakeTLS:      ${CLOAK_DOMAIN}

Telegram:     ${TG_LINK}
HTTPS link:   ${TG_HTTPS}
Dashboard:    ${DASH_URL}

SSH:          ssh -i ${INSTALL_DIR}/keys/mtproxy_ed25519 root@${SERVER_IP}

Generated:    $(date -u +"%Y-%m-%d %H:%M:%S UTC")
═══════════════════════════════════════════
INFOEOF
chmod 600 CONNECTION_INFO.txt

# ── Output ─────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════"
echo -e "  ${GREEN}Deployment Complete${NC}"
echo "═══════════════════════════════════════════"
echo ""
echo -e "${CYAN}Telegram:${NC}"
echo "  ${TG_LINK}"
echo ""
echo -e "${CYAN}Dashboard:${NC}"
echo "  ${DASH_URL}"
echo ""
echo -e "${CYAN}SSH:${NC}"
echo "  ssh -i ${INSTALL_DIR}/keys/mtproxy_ed25519 root@${SERVER_IP}"
echo ""

if [ ${ERRORS} -gt 0 ]; then
  echo -e "${RED}WARNING: ${ERRORS} service(s) failed!${NC}"
  echo "Check logs: cd ${INSTALL_DIR} && docker compose logs"
else
  echo -e "${GREEN}All services running.${NC}"
fi

echo ""
echo "Connection info saved: ${INSTALL_DIR}/CONNECTION_INFO.txt"
echo "SSH private key:       ${INSTALL_DIR}/keys/mtproxy_ed25519"
