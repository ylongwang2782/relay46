# Relay46

Deploy a dual-path reverse proxy for home NAS using Docker Compose: IPv4 traffic relays through a VPS, while IPv6 clients connect directly — same URL, automatic path selection via [Happy Eyeballs](https://en.wikipedia.org/wiki/Happy_Eyeballs).

## Why

Exposing home services to the internet is painful when you only have a dynamic IPv6 address and no public IPv4. Common solutions like Cloudflare Tunnels or frp add latency to every request. Relay46 takes a different approach:

- **IPv6 clients** (most modern networks) connect directly to NAS — ~20ms
- **IPv4 clients** fall back through VPS — works everywhere, slightly slower
- **Same URL** — the browser picks the fastest path automatically

## Features

- **Dual-path architecture** — IPv4 via VPS relay, IPv6 direct to NAS
- **Per-service routing** — each domain gets its own nginx server block with independent backend, WebSocket, timeout settings
- **Independent SSL certificates** — VPS uses HTTP-01 (webroot), NAS uses DNS-01 (Cloudflare) — no cross-machine SSH dependency
- **TCP stream proxy** — forward SSH, databases, and other TCP services
- **DDNS updater** — automatic Cloudflare AAAA record updates for dynamic IPv6
- **Custom HTTPS port** — when port 443 is occupied (e.g. by Xray), use any port like 8444
- **Local backend support** — proxy to other LAN devices (VMs, IoT) through NAS
- **One-command deployment** — `python3 deploy.py` handles everything

## Architecture

```
                         ┌─────────────────────────────────┐
                         │      VPS (host network)         │
                         │                                 │
  IPv4 ── A record ────► │  nginx (:8444) ───────────────────► NAS backend
          :8444          │  nginx stream (:2222, :2223) ──────► NAS SSH
                         │  certbot (webroot, HTTP-01)     │
                         │  xray (:443, independent)       │
                         └─────────────────────────────────┘

                         ┌─────────────────────────────────┐
                         │            NAS                   │
                         │                                 │
  IPv6 ── AAAA record ─► │  nginx (:8443/:8444) ───────────► local services
          :8444          │  certbot (dns-cloudflare, DNS-01)│
                         │  ddns-updater (Cloudflare AAAA) │
                         └─────────────────────────────────┘
```

Both paths terminate HTTPS independently. The browser resolves both A and AAAA records for the same domain and connects to whichever responds first.

## Quick Start

```bash
# 1. Clone
git clone https://github.com/ylongwang2782/relay46.git
cd relay46

# 2. Configure SSH key authentication
ssh-copy-id root@YOUR_VPS_IP
ssh-copy-id user@YOUR_NAS_HOST

# 3. Create configuration
cp config.example.yaml config.yaml
vim config.yaml

# 4. Deploy
pip3 install pyyaml
python3 deploy.py
```

## Requirements

- Python 3.6+ with PyYAML
- SSH key authentication to VPS and NAS
- Docker on VPS and NAS (auto-installed if missing)
- Cloudflare-managed domain (for DDNS and NAS DNS-01 certificates)

## Configuration

See [`config.example.yaml`](config.example.yaml) for the full template. Key sections:

### Server (VPS)

```yaml
server:
  host: "YOUR_VPS_IP"
  port: 22
  user: "root"
  http_port: 80      # ACME challenge listener
  https_port: 8444   # reverse proxy port (use non-443 if Xray occupies 443)
```

### NAS

```yaml
nas:
  host: "nas"        # SSH config alias or direct hostname
  user: "your_user"
  # deploy_path: "~/relay46"
```

### Services

```yaml
services:
  # Service running on NAS itself
  - name: "web-panel"
    domain: "panel.example.com"
    backend_port: 5666
    websocket: true
    host_header: "frontend"    # forward original Host header
    timeout:
      connect: 60
      send: 60
      read: 60

  # Service running on a different LAN device (VM, IoT, etc.)
  - name: "router"
    domain: "router.example.com"
    backend_port: 8082             # VPS → NAS relay port
    local_backend: "192.168.0.2:80"  # NAS → LAN device
    websocket: true
    host_header: "backend"         # forward backend address as Host

tcp_services:
  - name: "ssh"
    listen_port: 2222
    backend_port: 22

  - name: "router-ssh"
    listen_port: 2223
    backend_port: 2223
    local_backend: "192.168.0.2:22"  # NAS → LAN device SSH
```

### Cloudflare DNS (Optional)

```yaml
cloudflare:
  enabled: true
  api_token: "YOUR_API_TOKEN"   # Zone:DNS:Edit permission
  zone_id: "YOUR_ZONE_ID"
  proxied: false
```

When enabled, `deploy.py` automatically creates/updates A records (→ VPS IPv4) and AAAA records (→ NAS IPv6) for all service domains.

## Deployment Structure

### VPS (`/opt/relay46/`)

```
├── docker-compose.yaml          # nginx-proxy (host network), certbot
├── nginx/
│   ├── nginx.conf
│   ├── conf.d/nas_proxy.conf    # per-service HTTPS server blocks
│   └── stream.conf.d/tcp_proxy.conf
├── certs/                       # Let's Encrypt certificates (HTTP-01)
├── webroot/                     # ACME challenge directory
└── sync-cert-to-nas.sh          # legacy cert sync script (unused)
```

### NAS (`~/relay46/`)

```
├── docker-compose.yaml          # nginx-proxy, certbot, ddns-updater
├── nginx/nginx.conf             # per-service HTTPS server blocks + HTTP relay + TCP stream
├── certs/                       # Let's Encrypt certificates (DNS-01)
├── cloudflare.ini               # Cloudflare API token for certbot
├── ddns-script.sh               # Cloudflare AAAA record updater
├── .env                         # DDNS environment variables
└── logs/
```

## Certificate Management

VPS and NAS obtain certificates independently — no cross-machine SSH or certificate sync required.

| | VPS | NAS |
|--|-----|-----|
| Challenge type | HTTP-01 (webroot) | DNS-01 (Cloudflare) |
| Renewal | cron, twice daily | cron, twice daily |
| Dependency | Port 80 accessible | Cloudflare API token |

This design ensures that a compromised VPS cannot access the NAS.

## SSH Config Example

```
# ~/.ssh/config

Host vps
    HostName YOUR_VPS_IP
    User root

Host nas
    HostName YOUR_VPS_IP
    Port 2222
    User your_user
```

## Useful Commands

```bash
# Deploy / update
python3 deploy.py

# VPS status
ssh vps "cd /opt/relay46 && docker compose ps"
ssh vps "cd /opt/relay46 && docker compose logs -f nginx-proxy"

# NAS status
ssh nas "cd ~/relay46 && docker compose ps"
ssh nas "cat ~/relay46/logs/ddns.log"

# Manual certificate renewal
ssh vps "cd /opt/relay46 && docker compose run --rm certbot renew"
ssh nas "cd ~/relay46 && docker compose run --rm certbot renew"
```

## Proxy Client Recommendation

**Do not use Clash TUN mode** (or similar global transparent proxy modes like Clash Verge Rev TUN/fake-ip). TUN mode intercepts all system traffic at the network layer, which causes numerous issues with Relay46:

- **Breaks Happy Eyeballs** — TUN captures DNS and routes all traffic through the proxy, preventing the browser from selecting the faster IPv6 direct path. All requests are forced through the VPS relay (~1.4s) instead of connecting directly to NAS (~20ms).
- **fake-ip conflicts** — fake-ip mode returns spoofed DNS results, breaking AAAA record resolution and making IPv6 direct access impossible.
- **Hard to debug** — connection failures, certificate errors, and WebSocket timeouts become difficult to diagnose when traffic is silently intercepted by a TUN interface.
- **Split DNS bypass** — local DNS rules (e.g. dnsmasq on iStoreOS) are ignored because TUN hijacks DNS queries before they reach the local resolver.

**Recommended: use manual proxy in the terminal instead.** Only proxy traffic that actually needs it, and leave everything else on the default network path:

```bash
# Set proxy only when needed (e.g. for pulling Docker images, pip install, etc.)
export http_proxy=http://PROXY_HOST:PORT
export https_proxy=http://PROXY_HOST:PORT

# Or per-command
https_proxy=http://PROXY_HOST:PORT curl https://example.com
```

This keeps Relay46's dual-path architecture working correctly — your browser uses Happy Eyeballs to pick the fastest path, and local DNS resolution stays intact.

## Notes

- `config.yaml` contains secrets and is excluded via `.gitignore`
- DNS A records should point to VPS IPv4, AAAA to NAS IPv6
- VPS `nginx-proxy` uses host network mode for IPv6 connectivity to NAS backend
- NAS Docker may need a proxy to pull images if Docker Hub is blocked (configure via systemd drop-in)
- DDNS updater checks for IPv6 changes every 5 minutes
- HTTPS port can be customized via `server.https_port` (default 443)

## License

MIT
