# CloudOps Central — Multi-Cloud Monitoring Platform

## Quick Start (Linux — One Click)

### Step 1 — Copy project to your Linux server

```bash
# From your Windows machine, SCP the project:
scp -r "cloudops-central" user@YOUR_SERVER_IP:/opt/cloudops

# OR clone from git if you have a repo:
git clone https://github.com/yourrepo/cloudops-central /opt/cloudops
```

### Step 2 — Run the deploy script

```bash
cd /opt/cloudops

# Make scripts executable
chmod +x deploy.sh manage.sh

# Deploy with Docker (recommended)
sudo bash deploy.sh

# OR deploy without Docker (Python + systemd)
sudo bash deploy.sh --no-docker
```

The script will:
- Install Docker (or Python + nginx)
- Ask you to set `ADMIN_PASSWORD` and `VIEWER_PASSWORD`
- Auto-generate a secure `SECRET_KEY`
- Configure CORS and frontend API URL for your server IP
- Start all services
- Open firewall ports

### Step 3 — Open in browser

```
Frontend : http://YOUR_SERVER_IP:8001
API Docs : http://YOUR_SERVER_IP:8000/docs
```

Login with:
- Username: `admin` / Password: what you set during deploy
- Username: `viewer` / Password: what you set during deploy

---

## Management Commands

```bash
sudo ./manage.sh status    # Check if services are running
sudo ./manage.sh logs      # Stream live logs
sudo ./manage.sh restart   # Restart all services
sudo ./manage.sh stop      # Stop all services
sudo ./manage.sh start     # Start all services
sudo ./manage.sh update    # Pull latest code and rebuild
sudo ./manage.sh backup    # Backup .env and database
```

---

## Manual Linux Deployment (step by step)

### With Docker

```bash
# 1. Install Docker
curl -fsSL https://get.docker.com | sh
sudo systemctl enable --now docker

# 2. Create .env
cd /opt/cloudops/backend
cp .env.example .env
nano .env   # Fill in SECRET_KEY, ADMIN_PASSWORD, VIEWER_PASSWORD

# 3. Update frontend to point to your server IP
sed -i 's|const API_BASE = .*|const API_BASE = "http://YOUR_IP:8000";|' frontend/api_client.js

# 4. Start
cd /opt/cloudops
docker compose up -d --build

# 5. Check
docker compose ps
docker compose logs -f
```

### Without Docker (Python + systemd)

```bash
# 1. Install dependencies
sudo apt update && sudo apt install -y python3.12 python3.12-venv nginx

# 2. Setup virtualenv
cd /opt/cloudops/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Create .env
cp .env.example .env
nano .env   # Fill in SECRET_KEY, ADMIN_PASSWORD, VIEWER_PASSWORD

# 4. Create systemd service
sudo nano /etc/systemd/system/cloudops.service
```

Paste:
```ini
[Unit]
Description=CloudOps Central Backend
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/cloudops/backend
EnvironmentFile=/opt/cloudops/backend/.env
ExecStart=/opt/cloudops/backend/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
# 5. Start backend
sudo systemctl daemon-reload
sudo systemctl enable --now cloudops

# 6. Configure nginx for frontend
sudo cp /opt/cloudops/nginx.conf /etc/nginx/conf.d/cloudops.conf
sudo cp -r /opt/cloudops/frontend/* /var/www/html/
sudo systemctl enable --now nginx

# 7. Open firewall
sudo ufw allow 8000/tcp
sudo ufw allow 8001/tcp
```

---

## Windows Deployment

Double-click `start.bat` — it handles everything automatically.

---

## Files to change when moving to a different server

| File | What to change |
|---|---|
| `frontend/api_client.js` | `API_BASE` → your server IP/domain |
| `backend/.env` | `ALLOWED_ORIGINS` → your server IP/domain |
| `nginx.conf` | `connect-src` in CSP header |

---

## Troubleshooting

**Login fails:**
```bash
# Check backend is running
curl http://localhost:8000/health

# Check logs
sudo journalctl -u cloudops -n 50        # systemd
docker compose logs backend              # Docker
```

**CORS error in browser console:**
- Open `backend/.env`
- Add your server IP to `ALLOWED_ORIGINS`
- Restart: `sudo ./manage.sh restart`

**Port already in use:**
```bash
sudo lsof -i :8000
sudo lsof -i :8001
```

**Reset everything:**
```bash
# Docker
cd /opt/cloudops && docker compose down -v && docker compose up -d --build

# systemd
sudo systemctl stop cloudops
rm /opt/cloudops/backend/cloudops.db
sudo systemctl start cloudops
```

---

## Security Checklist for Production

- [ ] Change default passwords (min 12 chars, 1 uppercase, 1 digit)
- [ ] Set a strong `SECRET_KEY` (32+ chars)
- [ ] Restrict `ALLOWED_ORIGINS` to your exact domain
- [ ] Put behind HTTPS (use Certbot + Let's Encrypt)
- [ ] Do not expose port `8000` publicly — proxy through nginx
- [ ] Enable UFW / firewalld
- [ ] Set up regular backups: `sudo ./manage.sh backup`
