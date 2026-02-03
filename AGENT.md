# Relay46 Project Documentation

## Overview

Relay46 is a Docker Compose based reverse proxy deployment tool that configures a VPS (dual-stack) as a traffic relay for a home NAS (IPv6 only).

## Core Features

1. **HTTP/HTTPS Reverse Proxy** - WebSocket support, automatic Let's Encrypt certificates
2. **TCP Stream Proxy** - Forward SSH, databases, and other TCP services via Nginx stream
3. **Certificate Auto-Sync** - VPS certificates synced to NAS after renewal
4. **IPv4/IPv6 Dual-Stack** - IPv4 via VPS proxy, IPv6 direct to NAS
5. **DDNS Updater** - Automatic Cloudflare AAAA record updates for dynamic IPv6

## Architecture

```
IPv4 User → domain.com:443 → VPS Docker (nginx-proxy, host network) → NAS:port (via IPv6)
IPv6 User → domain.com:443 → NAS iptables:8443 → NAS Docker (nginx-proxy) → NAS:port
SSH User  → VPS:2222 → NAS:22 (via Nginx stream over IPv6)
```

### VPS Deployment Structure

```
/opt/relay46/
├── docker-compose.yaml      # VPS services (nginx-proxy with host network, certbot)
├── nginx/
│   ├── nginx.conf           # Main nginx config
│   ├── conf.d/
│   │   └── nas_proxy.conf   # HTTP/HTTPS reverse proxy rules
│   └── stream.conf.d/
│       └── tcp_proxy.conf   # TCP stream proxy rules
├── certs/                   # Let's Encrypt certificates
├── webroot/                 # ACME challenge files
└── sync-cert-to-nas.sh      # Certificate sync script
```

### NAS Deployment Structure

```
~/relay46/
├── docker-compose.yaml      # NAS services (nginx-proxy, ddns-updater)
├── nginx/
│   └── nginx.conf           # HTTPS termination config
├── certs/
│   ├── fullchain.crt        # Certificate (synced from VPS)
│   └── private.key          # Private key (synced from VPS)
├── ddns-script.sh           # Cloudflare DDNS update script
├── .env                     # Cloudflare credentials
└── logs/
    └── ddns.log             # DDNS update logs
```

## File Structure

```
relay46/
├── deploy.py                # Main deployment script (Python)
├── config.yaml              # User configuration (contains secrets, not committed)
├── config.example.yaml      # Configuration template
├── templates/               # Template files (reference only, not used at runtime)
│   ├── vps/                 # VPS templates
│   └── nas/                 # NAS templates
├── README.md                # User documentation
├── AGENT.md                 # Project documentation (this file)
└── .gitignore               # Excludes config.yaml etc.
```

## Configuration (config.yaml)

```yaml
server:           # VPS SSH configuration
  host: "IP"
  port: 22
  user: "root"
  # identity_file: "~/.ssh/id_ed25519"

nas:              # NAS SSH configuration (accessed via VPS SSH tunnel)
  host: "nas"     # SSH config alias that uses VPS:2222
  user: "username"
  # deploy_path: "~/relay46"

ssl:              # Let's Encrypt configuration
  email: "admin@example.com"

backend:          # NAS backend address (IPv6 DDNS domain)
  host: "nas.example.com"

cloudflare:       # Optional: Cloudflare DNS automation
  enabled: true
  api_token: "..."
  zone_id: "..."
  proxied: false

resolver:         # DNS resolver for dynamic backend resolution
  servers: ["8.8.8.8", "8.8.4.4"]
  ipv6: true

services:         # HTTP/HTTPS service list
  - name: "fnos"
    domain: "fnos.example.com"
    backend_port: 5666
    websocket: true
    host_header: "frontend"

  - name: "istoreos"           # Service with local_backend (VM/other device)
    domain: "istoreos.example.com"
    backend_port: 8082         # VPS connects to NAS on this port
    local_backend: "192.168.0.2:80"  # NAS proxies to this local address
    websocket: true
    host_header: "backend"

tcp_services:     # TCP service list
  - name: "ssh"
    listen_port: 2222
    backend_port: 22
```

## Deployment Script (deploy.py)

### Main Class: Relay46Deployer

**File Generation:**
- `_generate_vps_docker_compose()` - VPS docker-compose.yaml (host network mode)
- `_generate_vps_nginx_main_conf()` - VPS nginx main config
- `_generate_vps_http_proxy_conf()` - HTTP/HTTPS proxy rules
- `_generate_vps_stream_conf()` - TCP stream proxy rules
- `_generate_vps_sync_script()` - Certificate sync script
- `_generate_nas_docker_compose()` - NAS docker-compose.yaml (auto-exposes ports for local_backend services)
- `_generate_nas_nginx_conf()` - NAS nginx config (adds HTTP relay blocks for local_backend services)
- `_generate_nas_ddns_script()` - DDNS update script

**Certificate Management:**
- `check_certs_exist()` - Check if certificates exist on VPS
- `get_cert_domains()` - Get domains currently in the certificate
- `request_certificates()` - Request/renew certificates with automatic AAAA record handling
- `_temp_remove_aaaa_records()` - Temporarily remove AAAA records before cert request
- `_restore_aaaa_records()` - Restore AAAA records after cert request

**Deployment:**
- `test_connection()` - Test SSH connection
- `check_docker_installed()` - Check/install Docker
- `deploy_vps()` - Deploy configuration to VPS (auto-detects new domains needing certs)
- `deploy_nas()` - Deploy configuration to NAS
- `setup_cron()` - Configure certificate renewal cron job
- `verify_deployment()` - Verify containers are running

### Key Design Decisions

1. **VPS Host Network Mode**: nginx-proxy uses `network_mode: host` to access NAS via IPv6. Standard Docker bridge networking cannot route to external IPv6 addresses.

2. **Docker IPv6 Configuration**: VPS requires Docker IPv6 enabled in `/etc/docker/daemon.json`:
   ```json
   {
     "ipv6": true,
     "fixed-cidr-v6": "fd00::/80",
     "ip6tables": true,
     "experimental": true
   }
   ```

3. **NAS Access via SSH Tunnel**: During deployment, NAS is accessed through VPS port 2222 (SSH tunnel). The tunnel must be operational before NAS deployment.

## Docker Services

### VPS Services

| Service | Image | Network | Purpose |
|---------|-------|---------|---------|
| nginx-proxy | nginx:alpine | host | HTTP/HTTPS reverse proxy + TCP stream |
| certbot | certbot/certbot | - | SSL certificate management (on-demand) |

### NAS Services

| Service | Image | Network | Purpose |
|---------|-------|---------|---------|
| nginx-proxy | nginx:alpine | bridge | HTTPS termination for IPv6 direct access |
| ddns-updater | alpine:latest | host | Cloudflare AAAA record updater |

## Certificate Workflow

### Automatic AAAA Record Handling

When requesting certificates, the deployer automatically handles IPv6 (AAAA) records to prevent Let's Encrypt verification issues:

1. Detects which domains need to be added to the certificate
2. Temporarily removes AAAA records for those domains (prevents IPv6 verification which may fail if NAS doesn't handle ACME challenges)
3. Requests the certificate via IPv4 through VPS
4. Restores all AAAA records after certificate is obtained

This is handled by the `request_certificates()` method which is called automatically during deployment when new domains are detected.

### First-Time Deployment
1. Deploy nginx with HTTP-only config (for ACME challenge)
2. Temporarily remove AAAA records for all domains
3. Run certbot webroot challenge (via IPv4)
4. Restore AAAA records
5. Update nginx config with SSL
6. Reload nginx
7. Sync certificates to NAS (VPS → local → NAS)

### Renewal (Cron Job - twice daily)
```bash
cd /opt/relay46 && \
docker compose run --rm certbot renew --webroot -w /var/www/certbot && \
docker compose exec nginx-proxy nginx -s reload && \
/opt/relay46/sync-cert-to-nas.sh
```

## Local SSH Configuration

```
# ~/.ssh/config

Host vps relay46
    HostName YOUR_VPS_IP
    User root
    IdentityFile ~/.ssh/id_ed25519

Host nas fnos
    HostName YOUR_VPS_IP
    Port 2222
    User your_user
    IdentityFile ~/.ssh/id_ed25519
```

## Common Commands

```bash
# Deploy
python3 deploy.py

# Connect
ssh vps    # VPS direct
ssh nas    # NAS via VPS port 2222

# VPS Maintenance
ssh vps "cd /opt/relay46 && docker compose ps"
ssh vps "cd /opt/relay46 && docker compose logs -f nginx-proxy"
ssh vps "cd /opt/relay46 && docker compose run --rm certbot renew"

# NAS Maintenance
ssh nas "cd ~/relay46 && docker compose ps"
ssh nas "cd ~/relay46 && docker compose logs -f"
ssh nas "cat ~/relay46/logs/ddns.log"

# Manual cert sync (if needed)
scp vps:/opt/relay46/certs/live/DOMAIN/fullchain.pem /tmp/
scp vps:/opt/relay46/certs/live/DOMAIN/privkey.pem /tmp/
scp /tmp/fullchain.pem nas:~/relay46/certs/fullchain.crt
scp /tmp/privkey.pem nas:~/relay46/certs/private.key
ssh nas "cd ~/relay46 && docker compose exec nginx-proxy nginx -s reload"
```

## Notes

1. Configure SSH key authentication before deployment
2. config.yaml contains sensitive data and is excluded via .gitignore
3. DNS A records point to VPS, AAAA records point to NAS
4. NAS uses iptables to redirect :443 to :8443 for IPv6 direct access
5. Certificates auto-sync to NAS after VPS renewal (requires VPS→NAS SSH access)
6. DDNS updater runs every 5 minutes to update AAAA records
7. First deployment may require manual certificate sync due to SSH tunnel bootstrap
