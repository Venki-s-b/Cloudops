#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║          CloudOps Central — One-Click Linux Deployment Script              ║
# ║  Supports: Ubuntu 20.04/22.04/24.04, Debian 11/12, CentOS/RHEL 8/9        ║
# ║  Modes:                                                                     ║
# ║    ./deploy.sh              → Docker deployment (recommended)              ║
# ║    ./deploy.sh --no-docker  → Direct Python + systemd (no Docker)          ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()     { echo -e "${GREEN}[✓]${NC} $1"; }
info()    { echo -e "${BLUE}[i]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}══ $1 ══${NC}"; }

# ── Config ────────────────────────────────────────────────────────────────────
DEPLOY_DIR="/opt/cloudops"
APP_USER="cloudops"
BACKEND_PORT=8000
FRONTEND_PORT=8001
USE_DOCKER=true
SERVER_IP=$(hostname -I | awk '{print $1}')

# Parse args
for arg in "$@"; do
  [[ "$arg" == "--no-docker" ]] && USE_DOCKER=false
done

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║     CloudOps Central — Deployer       ║"
echo "  ║     Linux One-Click Setup v1.0        ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${NC}"
info "Server IP   : ${SERVER_IP}"
info "Deploy dir  : ${DEPLOY_DIR}"
info "Mode        : $([ "$USE_DOCKER" = true ] && echo 'Docker' || echo 'Direct Python + systemd')"
echo ""

# ── Must run as root ──────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run as root:  sudo bash deploy.sh"

# ── Detect OS ─────────────────────────────────────────────────────────────────
section "Detecting OS"
if   [[ -f /etc/os-release ]]; then source /etc/os-release; OS_ID=$ID; OS_VER=$VERSION_ID
else error "Cannot detect OS"; fi
log "Detected: $PRETTY_NAME"

# ── Install system packages ───────────────────────────────────────────────────
section "Installing System Packages"
case "$OS_ID" in
  ubuntu|debian)
    apt-get update -qq
    apt-get install -y -qq curl wget git python3 python3-pip python3-venv \
      nginx ufw openssl 2>/dev/null
    ;;
  centos|rhel|rocky|almalinux)
    dnf install -y curl wget git python3 python3-pip nginx firewalld openssl 2>/dev/null
    ;;
  *) warn "Unknown OS — skipping package install. Install manually if needed." ;;
esac
log "System packages ready"

# ── Copy project files ────────────────────────────────────────────────────────
section "Setting Up Project Directory"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$SCRIPT_DIR" != "$DEPLOY_DIR" ]]; then
  mkdir -p "$DEPLOY_DIR"
  cp -r "$SCRIPT_DIR"/. "$DEPLOY_DIR"/
  log "Project copied to $DEPLOY_DIR"
else
  log "Already in $DEPLOY_DIR"
fi

cd "$DEPLOY_DIR"

# ── Create app user ───────────────────────────────────────────────────────────
if ! id "$APP_USER" &>/dev/null; then
  useradd -r -s /bin/false -d "$DEPLOY_DIR" "$APP_USER"
  log "Created system user: $APP_USER"
fi
chown -R "$APP_USER":"$APP_USER" "$DEPLOY_DIR"

# ── Generate .env ─────────────────────────────────────────────────────────────
section "Configuring Environment"

ENV_FILE="$DEPLOY_DIR/backend/.env"

if [[ -f "$ENV_FILE" ]]; then
  warn ".env already exists — skipping generation (delete it to regenerate)"
else
  # Generate secret key
  SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

  # Prompt for passwords
  echo ""
  echo -e "${YELLOW}Set your admin password (min 12 chars, 1 uppercase, 1 digit):${NC}"
  while true; do
    read -rsp "  ADMIN_PASSWORD: " ADMIN_PASSWORD; echo
    if [[ ${#ADMIN_PASSWORD} -lt 12 ]]; then
      warn "Too short — minimum 12 characters"; continue
    fi
    if ! echo "$ADMIN_PASSWORD" | grep -q '[A-Z]'; then
      warn "Must contain at least 1 uppercase letter"; continue
    fi
    if ! echo "$ADMIN_PASSWORD" | grep -q '[0-9]'; then
      warn "Must contain at least 1 digit"; continue
    fi
    break
  done

  echo -e "${YELLOW}Set your viewer password (min 12 chars, 1 uppercase, 1 digit):${NC}"
  while true; do
    read -rsp "  VIEWER_PASSWORD: " VIEWER_PASSWORD; echo
    if [[ ${#VIEWER_PASSWORD} -lt 12 ]]; then
      warn "Too short — minimum 12 characters"; continue
    fi
    if ! echo "$VIEWER_PASSWORD" | grep -q '[A-Z]'; then
      warn "Must contain at least 1 uppercase letter"; continue
    fi
    if ! echo "$VIEWER_PASSWORD" | grep -q '[0-9]'; then
      warn "Must contain at least 1 digit"; continue
    fi
    break
  done

  # Write .env
  cat > "$ENV_FILE" <<EOF
SECRET_KEY=${SECRET_KEY}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
VIEWER_PASSWORD=${VIEWER_PASSWORD}
DATABASE_URL=sqlite:////data/cloudops.db
ALLOWED_ORIGINS=http://${SERVER_IP}:${FRONTEND_PORT},http://localhost:${FRONTEND_PORT},http://127.0.0.1:${FRONTEND_PORT}
ADMIN_EMAIL=admin@company.com
VIEWER_EMAIL=viewer@company.com
AWS_DEFAULT_REGION=us-east-1
CACHE_TTL=90
EOF

  chmod 600 "$ENV_FILE"
  chown "$APP_USER":"$APP_USER" "$ENV_FILE"
  log ".env created with generated SECRET_KEY"
fi

# Load env vars for use below
set -a; source "$ENV_FILE"; set +a

# ── Update frontend API_BASE to point to this server ─────────────────────────
section "Configuring Frontend"
API_CLIENT="$DEPLOY_DIR/frontend/api_client.js"
sed -i "s|const API_BASE = .*|const API_BASE = \"http://${SERVER_IP}:${BACKEND_PORT}\";|" "$API_CLIENT"
log "api_client.js → API_BASE set to http://${SERVER_IP}:${BACKEND_PORT}"

# ── Update nginx CSP header ───────────────────────────────────────────────────
NGINX_CONF="$DEPLOY_DIR/nginx.conf"
sed -i "s|connect-src 'self' http://localhost:8000|connect-src 'self' http://${SERVER_IP}:${BACKEND_PORT} http://localhost:${BACKEND_PORT}|" "$NGINX_CONF"
log "nginx.conf → CSP connect-src updated"

# ══════════════════════════════════════════════════════════════════════════════
# DOCKER DEPLOYMENT
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$USE_DOCKER" == true ]]; then

  section "Installing Docker"
  if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
    log "Docker installed and started"
  else
    log "Docker already installed: $(docker --version)"
  fi

  if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
    curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$(uname -m)" \
      -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    log "docker-compose installed"
  else
    log "docker-compose already available"
  fi

  section "Building and Starting Containers"
  cd "$DEPLOY_DIR"

  # Update docker-compose ALLOWED_ORIGINS
  sed -i "s|ALLOWED_ORIGINS:.*|ALLOWED_ORIGINS: \"http://${SERVER_IP}:${FRONTEND_PORT},http://localhost:${FRONTEND_PORT}\"|" docker-compose.yml

  # Stop existing containers if running
  docker compose down 2>/dev/null || docker-compose down 2>/dev/null || true

  # Build and start
  if docker compose version &>/dev/null 2>&1; then
    docker compose --env-file backend/.env up -d --build
  else
    docker-compose --env-file backend/.env up -d --build
  fi

  log "Containers started"

  # ── Firewall ────────────────────────────────────────────────────────────────
  section "Configuring Firewall"
  if command -v ufw &>/dev/null; then
    ufw allow ssh    2>/dev/null || true
    ufw allow "$BACKEND_PORT"/tcp  2>/dev/null || true
    ufw allow "$FRONTEND_PORT"/tcp 2>/dev/null || true
    ufw --force enable 2>/dev/null || true
    log "ufw: ports $BACKEND_PORT and $FRONTEND_PORT opened"
  elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port="$BACKEND_PORT"/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port="$FRONTEND_PORT"/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    log "firewalld: ports $BACKEND_PORT and $FRONTEND_PORT opened"
  fi

# ══════════════════════════════════════════════════════════════════════════════
# DIRECT PYTHON + SYSTEMD DEPLOYMENT (no Docker)
# ══════════════════════════════════════════════════════════════════════════════
else

  section "Setting Up Python Virtual Environment"
  VENV="$DEPLOY_DIR/backend/venv"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --upgrade pip --quiet
  "$VENV/bin/pip" install -r "$DEPLOY_DIR/backend/requirements.txt" --quiet
  chown -R "$APP_USER":"$APP_USER" "$VENV"
  log "Python venv ready at $VENV"

  # ── systemd service for backend ─────────────────────────────────────────────
  section "Creating systemd Service"
  cat > /etc/systemd/system/cloudops.service <<EOF
[Unit]
Description=CloudOps Central Backend
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${DEPLOY_DIR}/backend
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV}/bin/uvicorn main:app --host 0.0.0.0 --port ${BACKEND_PORT} --workers 4
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cloudops

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable cloudops
  systemctl restart cloudops
  log "cloudops.service enabled and started"

  # ── nginx for frontend ───────────────────────────────────────────────────────
  section "Configuring Nginx Frontend"

  # Create data dir for DB
  mkdir -p /data
  chown "$APP_USER":"$APP_USER" /data

  # Write nginx site config
  cat > /etc/nginx/conf.d/cloudops.conf <<EOF
server {
    listen ${FRONTEND_PORT};
    server_name _;

    root ${DEPLOY_DIR}/frontend;
    index index.html;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' http://${SERVER_IP}:${BACKEND_PORT} http://localhost:${BACKEND_PORT};" always;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location ~* \.(js|css|png|jpg|ico|woff2)$ {
        expires 7d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

  # Remove default nginx site if it conflicts
  rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

  nginx -t && systemctl enable nginx && systemctl restart nginx
  log "Nginx configured and restarted"

  # ── Firewall ─────────────────────────────────────────────────────────────────
  section "Configuring Firewall"
  if command -v ufw &>/dev/null; then
    ufw allow ssh    2>/dev/null || true
    ufw allow "$BACKEND_PORT"/tcp  2>/dev/null || true
    ufw allow "$FRONTEND_PORT"/tcp 2>/dev/null || true
    ufw --force enable 2>/dev/null || true
    log "ufw: ports $BACKEND_PORT and $FRONTEND_PORT opened"
  elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port="$BACKEND_PORT"/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port="$FRONTEND_PORT"/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    log "firewalld: ports $BACKEND_PORT and $FRONTEND_PORT opened"
  fi

fi

# ── Health check ──────────────────────────────────────────────────────────────
section "Verifying Deployment"
sleep 5
if curl -sf "http://localhost:${BACKEND_PORT}/health" > /dev/null 2>&1; then
  log "Backend health check PASSED"
else
  warn "Backend health check failed — check logs:"
  if [[ "$USE_DOCKER" == true ]]; then
    echo "  docker compose logs backend"
  else
    echo "  journalctl -u cloudops -n 50"
  fi
fi

# ── Print summary ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║         CloudOps Central — Deployed!                ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Frontend  :${NC}  http://${SERVER_IP}:${FRONTEND_PORT}"
echo -e "  ${BOLD}Backend   :${NC}  http://${SERVER_IP}:${BACKEND_PORT}"
echo -e "  ${BOLD}API Docs  :${NC}  http://${SERVER_IP}:${BACKEND_PORT}/docs"
echo ""
echo -e "  ${BOLD}Login credentials:${NC}"
echo -e "    Username: ${CYAN}admin${NC}   Password: ${YELLOW}(what you set above)${NC}"
echo -e "    Username: ${CYAN}viewer${NC}  Password: ${YELLOW}(what you set above)${NC}"
echo ""
if [[ "$USE_DOCKER" == true ]]; then
  echo -e "  ${BOLD}Useful commands:${NC}"
  echo -e "    View logs   :  cd $DEPLOY_DIR && docker compose logs -f"
  echo -e "    Restart     :  cd $DEPLOY_DIR && docker compose restart"
  echo -e "    Stop        :  cd $DEPLOY_DIR && docker compose down"
  echo -e "    Update      :  cd $DEPLOY_DIR && git pull && docker compose up -d --build"
else
  echo -e "  ${BOLD}Useful commands:${NC}"
  echo -e "    View logs   :  journalctl -u cloudops -f"
  echo -e "    Restart     :  systemctl restart cloudops"
  echo -e "    Stop        :  systemctl stop cloudops"
  echo -e "    Status      :  systemctl status cloudops"
fi
echo ""
