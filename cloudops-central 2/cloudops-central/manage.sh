#!/bin/bash
# CloudOps Central — Management Script
# Usage: ./manage.sh [start|stop|restart|status|logs|update|backup]

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

DEPLOY_DIR="/opt/cloudops"
BACKUP_DIR="/opt/cloudops-backups"

log()   { echo -e "${GREEN}[✓]${NC} $1"; }
info()  { echo -e "${CYAN}[i]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# Detect deployment mode
USE_DOCKER=false
if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
  if [[ -f "$DEPLOY_DIR/docker-compose.yml" ]]; then
    USE_DOCKER=true
  fi
fi

cd "$DEPLOY_DIR" 2>/dev/null || error "Deploy dir $DEPLOY_DIR not found. Run deploy.sh first."

case "${1:-help}" in

  start)
    info "Starting CloudOps Central..."
    if [[ "$USE_DOCKER" == true ]]; then
      docker compose --env-file backend/.env up -d
    else
      systemctl start cloudops nginx
    fi
    log "Started"
    ;;

  stop)
    info "Stopping CloudOps Central..."
    if [[ "$USE_DOCKER" == true ]]; then
      docker compose down
    else
      systemctl stop cloudops
    fi
    log "Stopped"
    ;;

  restart)
    info "Restarting CloudOps Central..."
    if [[ "$USE_DOCKER" == true ]]; then
      docker compose restart
    else
      systemctl restart cloudops nginx
    fi
    log "Restarted"
    ;;

  status)
    echo -e "\n${BOLD}CloudOps Central — Status${NC}\n"
    if [[ "$USE_DOCKER" == true ]]; then
      docker compose ps
    else
      systemctl status cloudops --no-pager -l
      echo ""
      systemctl status nginx --no-pager -l
    fi
    echo ""
    SERVER_IP=$(hostname -I | awk '{print $1}')
    if curl -sf "http://localhost:8000/health" > /dev/null 2>&1; then
      log "Backend  http://${SERVER_IP}:8000  ✓ ONLINE"
    else
      warn "Backend  http://${SERVER_IP}:8000  ✗ OFFLINE"
    fi
    if curl -sf "http://localhost:8001" > /dev/null 2>&1; then
      log "Frontend http://${SERVER_IP}:8001  ✓ ONLINE"
    else
      warn "Frontend http://${SERVER_IP}:8001  ✗ OFFLINE"
    fi
    ;;

  logs)
    info "Streaming logs (Ctrl+C to stop)..."
    if [[ "$USE_DOCKER" == true ]]; then
      docker compose logs -f --tail=100
    else
      journalctl -u cloudops -f --no-pager
    fi
    ;;

  update)
    info "Pulling latest code and rebuilding..."
    git pull origin main 2>/dev/null || warn "git pull failed — update files manually"
    if [[ "$USE_DOCKER" == true ]]; then
      docker compose --env-file backend/.env up -d --build
    else
      source backend/venv/bin/activate
      pip install -r backend/requirements.txt --quiet
      systemctl restart cloudops
    fi
    log "Update complete"
    ;;

  backup)
    info "Creating backup..."
    mkdir -p "$BACKUP_DIR"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="$BACKUP_DIR/cloudops_backup_${TIMESTAMP}.tar.gz"
    tar -czf "$BACKUP_FILE" \
      --exclude="$DEPLOY_DIR/backend/venv" \
      --exclude="$DEPLOY_DIR/backend/__pycache__" \
      --exclude="$DEPLOY_DIR/.git" \
      "$DEPLOY_DIR/backend/.env" \
      "$DEPLOY_DIR/backend/cloudops.db" \
      2>/dev/null || true
    log "Backup saved: $BACKUP_FILE"
    ls -lh "$BACKUP_DIR"
    ;;

  help|*)
    echo -e "\n${BOLD}CloudOps Central — Management Script${NC}"
    echo ""
    echo "  Usage: sudo ./manage.sh <command>"
    echo ""
    echo "  Commands:"
    echo -e "    ${CYAN}start${NC}    — Start all services"
    echo -e "    ${CYAN}stop${NC}     — Stop all services"
    echo -e "    ${CYAN}restart${NC}  — Restart all services"
    echo -e "    ${CYAN}status${NC}   — Show service status + health check"
    echo -e "    ${CYAN}logs${NC}     — Stream live logs"
    echo -e "    ${CYAN}update${NC}   — Pull latest code and rebuild"
    echo -e "    ${CYAN}backup${NC}   — Backup .env and database"
    echo ""
    ;;
esac
