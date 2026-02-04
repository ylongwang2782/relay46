# Relay46 - Docker Compose Nginx Reverse Proxy

Deploy a VPS (dual-stack) as a reverse proxy for a home NAS (IPv6 only) using Docker Compose.

## Features

- **HTTP/HTTPS Reverse Proxy**: WebSocket support, automatic SSL certificates
- **TCP Stream Proxy**: Forward SSH, databases, and other TCP services
- **IPv6 Direct Access**: NAS Docker nginx for IPv6 clients
- **Certificate Auto-Sync**: Sync Let's Encrypt certs to NAS after renewal
- **DDNS Updater**: Automatic Cloudflare AAAA record updates
- **Docker Compose**: Easy deployment and management

## Quick Start

```bash
# 1. Clone repository
git clone https://github.com/ylongwang2782/relay46.git
cd relay46

# 2. Configure SSH key authentication
ssh-copy-id root@YOUR_VPS_IP
ssh-copy-id user@YOUR_NAS_HOST  # Direct access or via VPS tunnel

# 3. Create configuration file
cp config.example.yaml config.yaml
vim config.yaml

# 4. Deploy
python3 deploy.py
```

## Requirements

- Python 3.6+
- SSH key authentication
- Docker on VPS and NAS (auto-installed if missing)

```bash
pip3 install pyyaml
```

## Configuration

### VPS (Server)

```yaml
server:
  host: "YOUR_VPS_IP"
  port: 22
  user: "root"
  # 可选: VPS HTTP/HTTPS 监听端口（默认 80/443）
  # 当 443 被其他服务占用时，可改为 8444 等端口
  http_port: 80
  https_port: 443
  # identity_file: "~/.ssh/id_ed25519"
```

### NAS

```yaml
nas:
  host: "nas"  # SSH config alias (via VPS:2222)
  user: "your_user"
  # deploy_path: "~/relay46"
```

### HTTP/HTTPS Services

```yaml
services:
  - name: "web-panel"
    domain: "panel.example.com"
    backend_port: 5666
    websocket: true
    host_header: "frontend"
```

### TCP Services

```yaml
tcp_services:
  - name: "ssh"
    listen_port: 2222
    backend_port: 22
```

### Cloudflare DNS (Optional)

```yaml
cloudflare:
  enabled: true
  api_token: "YOUR_API_TOKEN"
  zone_id: "YOUR_ZONE_ID"
  proxied: false
```

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │         VPS (host network)          │
                    │  ┌─────────────────────────────┐    │
IPv4 Client ──────► │  │  nginx-proxy (Docker)       │    │
      :443(*)       │  │  - HTTP/HTTPS reverse proxy │────┼───► NAS Backend
      :2222         │  │  - TCP stream proxy (IPv6)  │    │     (via IPv6)
                    │  └─────────────────────────────┘    │
                    │  ┌─────────────────────────────┐    │
                    │  │  certbot (Docker)           │    │
                    │  │  - Let's Encrypt certs      │    │
                    │  └─────────────────────────────┘    │
                    └─────────────────────────────────────┘

                    ┌─────────────────────────────────────┐
                    │              NAS                     │
                    │  ┌─────────────────────────────┐    │
IPv6 Client ──────► │  │  nginx-proxy (Docker)       │    │
      :443 ──► :8443│  │  - HTTPS termination        │────┼───► Local Services
                    │  └─────────────────────────────┘    │
                    │  ┌─────────────────────────────┐    │
                    │  │  ddns-updater (Docker)      │    │
                    │  │  - Cloudflare AAAA updates  │    │
                    │  └─────────────────────────────┘    │
                    └─────────────────────────────────────┘
```

## Deployment Structure

### VPS (/opt/relay46/)

```
/opt/relay46/
├── docker-compose.yaml       # nginx-proxy (host network), certbot
├── nginx/
│   ├── nginx.conf
│   ├── conf.d/nas_proxy.conf
│   └── stream.conf.d/tcp_proxy.conf
├── certs/                    # Let's Encrypt certificates
├── webroot/                  # ACME challenge
└── sync-cert-to-nas.sh       # Certificate sync script
```

### NAS (~/relay46/)

```
~/relay46/
├── docker-compose.yaml       # nginx-proxy, ddns-updater
├── nginx/nginx.conf
├── certs/                    # Synced from VPS
├── ddns-script.sh
├── .env                      # Cloudflare credentials
└── logs/ddns.log
```

## SSH Config Example

```
# ~/.ssh/config

Host vps
    HostName YOUR_VPS_IP
    User root
    IdentityFile ~/.ssh/id_ed25519

Host nas
    HostName YOUR_VPS_IP
    Port 2222
    User your_user
    IdentityFile ~/.ssh/id_ed25519
```

## Useful Commands

```bash
# Deploy/Update
python3 deploy.py

# VPS: Check container status
ssh vps "cd /opt/relay46 && docker compose ps"

# VPS: View nginx logs
ssh vps "cd /opt/relay46 && docker compose logs -f nginx-proxy"

# VPS: Manual certificate renewal
ssh vps "cd /opt/relay46 && docker compose run --rm certbot renew"

# NAS: Check container status
ssh nas "cd ~/relay46 && docker compose ps"

# NAS: View DDNS logs
ssh nas "cat ~/relay46/logs/ddns.log"

# Manual cert sync (first deployment or troubleshooting)
scp vps:/opt/relay46/certs/live/DOMAIN/fullchain.pem /tmp/fullchain.crt
scp vps:/opt/relay46/certs/live/DOMAIN/privkey.pem /tmp/private.key
scp /tmp/fullchain.crt /tmp/private.key nas:~/relay46/certs/
ssh nas "cd ~/relay46 && docker compose exec nginx-proxy nginx -s reload"
```

## IPv6 Direct Access Setup

For NAS to receive IPv6 traffic on port 443, use iptables to redirect to 8443:

```bash
# On NAS
ip6tables -t nat -A PREROUTING -d YOUR_NAS_IPV6 -p tcp --dport 443 -j REDIRECT --to-port 8443
```

## Migration from Previous Version

If upgrading from the system-level nginx installation:

1. Stop old nginx: `ssh vps "systemctl stop nginx && systemctl disable nginx"`
2. Backup certificates: `ssh vps "cp -r /etc/letsencrypt /opt/relay46/certs"`
3. Run new deployment: `python3 deploy.py`

## Notes

1. Configure SSH key authentication before deployment
2. config.yaml contains sensitive data (excluded via .gitignore)
3. DNS A records should point to VPS, AAAA to NAS
4. VPS nginx-proxy uses host network mode for IPv6 connectivity
5. Certificates auto-renew and sync to NAS twice daily
6. DDNS updater checks every 5 minutes for IPv6 changes
7. First deployment may require manual cert sync to NAS
8. `:443` 可通过 `server.https_port` 修改为其他端口
