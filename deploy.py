#!/usr/bin/env python3
"""
Relay46 - Docker Compose based reverse proxy deployment

Deploys nginx reverse proxy to VPS and NAS using Docker Compose:
    - VPS: HTTP/HTTPS reverse proxy + TCP stream + SSL certificates
    - NAS: HTTPS termination for IPv6 direct access + DDNS updater

Usage:
    1. Configure SSH key authentication (ssh-copy-id)
    2. Edit config.yaml
    3. Run: python3 deploy.py

Requirements:
    - Python 3.6+
    - PyYAML: pip3 install pyyaml
    - SSH key authentication
"""

import subprocess
import sys
import os
import json
import time
import urllib.request
import urllib.error
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Install PyYAML if not available
try:
    import yaml
except ImportError:
    print("Installing PyYAML...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])
    import yaml


class Relay46Deployer:
    """Docker Compose based deployment for relay46"""

    VPS_DEPLOY_PATH = "/opt/relay46"
    NAS_DEPLOY_PATH_DEFAULT = "~/relay46"

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.script_dir = Path(__file__).parent.resolve()

    def _load_config(self) -> dict:
        """Load YAML configuration file"""
        if not self.config_path.exists():
            print(f"Error: Config file {self.config_path} not found")
            sys.exit(1)

        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def _build_ssh_cmd(self, target: str = "server") -> List[str]:
        """Build SSH command with connection pooling"""
        if target == "server":
            cfg = self.config['server']
        elif target == "nas":
            cfg = self.config.get('nas', {})
            if not cfg:
                cfg = {'host': self.config['backend']['host'], 'user': 'root'}
        else:
            raise ValueError(f"Unknown target: {target}")

        control_path = f"/tmp/ssh-relay46-{cfg['host']}"
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=30",
            "-o", f"ControlPath={control_path}",
            "-o", "ControlMaster=auto",
            "-o", "ControlPersist=300",
        ]

        if 'port' in cfg:
            cmd.extend(["-p", str(cfg['port'])])

        if 'identity_file' in cfg:
            identity = os.path.expanduser(cfg['identity_file'])
            cmd.extend(["-i", identity])

        cmd.append(f"{cfg['user']}@{cfg['host']}")
        return cmd

    def _ssh_cmd(self, command: str, target: str = "server", timeout: int = 120) -> Tuple[int, str, str]:
        """Execute remote SSH command"""
        ssh_command = self._build_ssh_cmd(target) + [command]

        try:
            result = subprocess.run(
                ssh_command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timeout"

    def _scp_file(self, local_path: str, remote_path: str, target: str = "server") -> Tuple[int, str, str]:
        """SCP file to remote host"""
        if target == "server":
            cfg = self.config['server']
        else:
            cfg = self.config.get('nas', {'host': self.config['backend']['host'], 'user': 'root'})

        control_path = f"/tmp/ssh-relay46-{cfg['host']}"
        cmd = [
            "scp",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", f"ControlPath={control_path}",
        ]

        if 'port' in cfg:
            cmd.extend(["-P", str(cfg['port'])])

        if 'identity_file' in cfg:
            identity = os.path.expanduser(cfg['identity_file'])
            cmd.extend(["-i", identity])

        cmd.extend([local_path, f"{cfg['user']}@{cfg['host']}:{remote_path}"])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "SCP timeout"

    def _scp_dir(self, local_path: str, remote_path: str, target: str = "server") -> Tuple[int, str, str]:
        """SCP directory recursively to remote host"""
        if target == "server":
            cfg = self.config['server']
        else:
            cfg = self.config.get('nas', {'host': self.config['backend']['host'], 'user': 'root'})

        control_path = f"/tmp/ssh-relay46-{cfg['host']}"
        cmd = [
            "scp", "-r",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", f"ControlPath={control_path}",
        ]

        if 'port' in cfg:
            cmd.extend(["-P", str(cfg['port'])])

        if 'identity_file' in cfg:
            identity = os.path.expanduser(cfg['identity_file'])
            cmd.extend(["-i", identity])

        cmd.extend([local_path, f"{cfg['user']}@{cfg['host']}:{remote_path}"])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "SCP timeout"

    def _print_step(self, step: int, total: int, message: str):
        """Print step information"""
        print(f"\n[{step}/{total}] {message}")
        print("=" * 50)

    # =========================================================================
    # VPS File Generation
    # =========================================================================

    def _generate_vps_docker_compose(self) -> str:
        """Generate VPS docker-compose.yaml"""
        # Use host network mode for IPv6 connectivity to NAS
        template = '''# VPS Docker Compose Configuration
# Auto-generated by relay46 deployer

services:
  nginx-proxy:
    image: nginx:alpine
    container_name: nginx-proxy
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./nginx/stream.conf.d:/etc/nginx/stream.conf.d:ro
      - ./certs:/etc/letsencrypt:ro
      - ./webroot:/var/www/certbot:ro

  certbot:
    image: certbot/certbot
    container_name: certbot
    volumes:
      - ./certs:/etc/letsencrypt
      - ./webroot:/var/www/certbot
    profiles:
      - certbot
'''
        return template

    def _generate_vps_nginx_main_conf(self) -> str:
        """Generate VPS nginx main config"""
        return '''# Main Nginx configuration for VPS
# Auto-generated by relay46 deployer

user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/rss+xml application/atom+xml image/svg+xml;

    include /etc/nginx/conf.d/*.conf;
}

stream {
    include /etc/nginx/stream.conf.d/*.conf;
}
'''

    def _generate_vps_http_proxy_conf(self, with_ssl: bool = True) -> str:
        """Generate VPS HTTP proxy configuration"""
        config = self.config
        resolver = config['resolver']
        backend = config['backend']
        services = config.get('services', [])
        server_cfg = config.get('server', {})
        http_port = int(server_cfg.get('http_port', 80))
        https_port = int(server_cfg.get('https_port', 443))
        https_port_suffix = "" if https_port == 443 else f":{https_port}"

        if not services:
            return "# No HTTP services configured\n"

        resolver_servers = " ".join(resolver['servers'])
        resolver_ipv6 = "ipv6=on" if resolver.get('ipv6', True) else "ipv6=off"

        nginx_config = f'''# ===========================================
# NAS HTTP/HTTPS Reverse Proxy Configuration
# Auto-generated by relay46 deployer
# Backend: {backend['host']}
# ===========================================

resolver {resolver_servers} {resolver_ipv6} valid={resolver.get('valid', '300s')};
resolver_timeout {resolver.get('timeout', '5s')};

# WebSocket connection upgrade mapping
map $http_upgrade $connection_upgrade {{
    default upgrade;
    ''      close;
}}

# ACME challenge server
server {{
    listen {http_port} default_server;
    listen [::]:{http_port} default_server;
    server_name _;

    location /.well-known/acme-challenge/ {{
        root /var/www/certbot;
    }}

    location / {{
        return 301 https://$host{https_port_suffix}$request_uri;
    }}
}}

'''

        if not with_ssl:
            # Generate temporary config for initial certificate request
            for service in services:
                domain = service['domain']
                nginx_config += f'''server {{
    listen {http_port};
    listen [::]:{http_port};
    server_name {domain};

    location /.well-known/acme-challenge/ {{
        root /var/www/certbot;
    }}

    location / {{
        return 200 "OK";
    }}
}}

'''
            return nginx_config

        # Generate full SSL config
        first_ssl_domain = services[0]['domain'] if services else None

        for i, service in enumerate(services):
            name = service['name']
            domain = service['domain']
            port = service['backend_port']
            websocket = service.get('websocket', False)
            host_header = service.get('host_header', 'frontend')
            timeout = service.get('timeout', {'connect': 60, 'send': 60, 'read': 60})

            ssl_domain = first_ssl_domain

            nginx_config += f'''# =====================
# {name.upper()}
# =====================
server {{
    listen {https_port} ssl http2;
    listen [::]:{https_port} ssl http2;
    server_name {domain};

    ssl_certificate /etc/letsencrypt/live/{ssl_domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{ssl_domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    set $backend_host "{backend['host']}";
    set $backend_port {port};

    location / {{
        proxy_pass http://$backend_host:$backend_port;

'''
            if host_header == 'backend':
                nginx_config += '        proxy_set_header Host $backend_host:$backend_port;\n'
            else:
                nginx_config += '        proxy_set_header Host $host;\n'

            nginx_config += '''        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_http_version 1.1;
'''
            if websocket:
                nginx_config += '''        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
'''
            else:
                nginx_config += '        proxy_set_header Connection "";\n'

            nginx_config += f'''
        proxy_connect_timeout {timeout.get('connect', 60)}s;
        proxy_send_timeout {timeout.get('send', 60)}s;
        proxy_read_timeout {timeout.get('read', 60)}s;

        proxy_buffering off;
        proxy_request_buffering off;
    }}
}}

'''

        return nginx_config

    def _generate_vps_stream_conf(self) -> str:
        """Generate VPS TCP stream configuration"""
        tcp_services = self.config.get('tcp_services', [])
        if not tcp_services:
            return "# No TCP services configured\n"

        backend = self.config['backend']['host']
        resolver = self.config['resolver']
        resolver_servers = " ".join(resolver['servers'])
        resolver_ipv6 = "ipv6=on" if resolver.get('ipv6', True) else "ipv6=off"

        stream_config = f'''# TCP Stream Proxy Configuration
# Auto-generated by relay46 deployer

resolver {resolver_servers} {resolver_ipv6} valid={resolver.get('valid', '300s')};
resolver_timeout {resolver.get('timeout', '5s')};

'''

        for svc in tcp_services:
            name = svc['name']
            listen_port = svc['listen_port']
            backend_port = svc['backend_port']

            stream_config += f'''# {name.upper()}
server {{
    listen {listen_port};
    listen [::]:{listen_port};
    proxy_pass {backend}:{backend_port};
    proxy_connect_timeout 60s;
    proxy_timeout 300s;
}}

'''

        return stream_config

    def _generate_vps_sync_script(self) -> str:
        """Generate certificate sync script for VPS"""
        nas_config = self.config.get('nas', {})
        services = self.config.get('services', [])

        if not services or not nas_config:
            return "#!/bin/bash\necho 'No NAS configured for cert sync'\n"

        domain = services[0]['domain']
        nas_host = nas_config.get('host', self.config['backend']['host'])
        nas_user = nas_config.get('user', 'root')
        nas_port = nas_config.get('port', '')
        nas_identity = nas_config.get('identity_file', '')
        nas_deploy_path = nas_config.get('deploy_path', self.NAS_DEPLOY_PATH_DEFAULT)

        # Build SSH options
        ssh_opts = "-o StrictHostKeyChecking=no -o BatchMode=yes"
        scp_opts = ""
        if nas_identity:
            ssh_opts += f' -i {nas_identity}'
        if nas_port:
            ssh_opts += f' -p {nas_port}'
            scp_opts = f'-P {nas_port}'

        return f'''#!/bin/bash
# SSL Certificate Sync Script - Sync to NAS Docker Nginx
# Auto-generated by relay46 deployer

set -e

DOMAIN="{domain}"
NAS_HOST="{nas_host}"
NAS_USER="{nas_user}"
CERT_DIR="/opt/relay46/certs/live/${{DOMAIN}}"
NAS_CERT_DIR="{nas_deploy_path}/certs"
SSH_OPTS="{ssh_opts}"
SCP_OPTS="{scp_opts}"

log() {{
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}}

if [ ! -f "${{CERT_DIR}}/fullchain.pem" ]; then
    log "ERROR: Certificate not found at ${{CERT_DIR}}"
    exit 1
fi

log "Syncing certificates to NAS..."

# Create remote directory if not exists
ssh $SSH_OPTS ${{NAS_USER}}@${{NAS_HOST}} "mkdir -p ${{NAS_CERT_DIR}}"

# Sync certificates
scp $SSH_OPTS $SCP_OPTS "${{CERT_DIR}}/fullchain.pem" "${{NAS_USER}}@${{NAS_HOST}}:${{NAS_CERT_DIR}}/fullchain.crt"
scp $SSH_OPTS $SCP_OPTS "${{CERT_DIR}}/privkey.pem" "${{NAS_USER}}@${{NAS_HOST}}:${{NAS_CERT_DIR}}/private.key"

# Reload NAS nginx
ssh $SSH_OPTS ${{NAS_USER}}@${{NAS_HOST}} "cd {nas_deploy_path} && docker compose exec -T nginx-proxy nginx -s reload 2>/dev/null || true"

log "Certificate sync completed!"
'''

    def _generate_vps_cron(self) -> str:
        """Generate cron job for certificate renewal"""
        return '''# Certbot renewal - runs twice daily
0 0,12 * * * cd /opt/relay46 && docker compose run --rm certbot renew --webroot -w /var/www/certbot && docker compose exec nginx-proxy nginx -s reload >> /var/log/cert-renewal.log 2>&1
'''

    # =========================================================================
    # NAS File Generation
    # =========================================================================

    def _generate_nas_docker_compose(self) -> str:
        """Generate NAS docker-compose.yaml"""
        cf_config = self.config.get('cloudflare', {})
        cf_enabled = cf_config.get('enabled', False)
        services = self.config.get('services', [])
        tcp_services = self.config.get('tcp_services', [])
        server_cfg = self.config.get('server', {})
        https_port = int(server_cfg.get('https_port', 443))

        # Collect ports for services with local_backend (HTTP and TCP)
        extra_ports = []
        for service in services:
            if service.get('local_backend'):
                port = service['backend_port']
                extra_ports.append(f'      - "{port}:{port}"')

        for tcp_svc in tcp_services:
            if tcp_svc.get('local_backend'):
                port = tcp_svc['backend_port']
                extra_ports.append(f'      - "{port}:{port}"')

        ports_section = '      - "8443:443"'
        if https_port != 8443:
            ports_section += f'\n      - "{https_port}:443"'
        if extra_ports:
            ports_section += '\n' + '\n'.join(extra_ports)

        compose = f'''# NAS Docker Compose Configuration
# Auto-generated by relay46 deployer

services:
  nginx-proxy:
    image: nginx:alpine
    container_name: nginx-proxy
    restart: unless-stopped
    ports:
{ports_section}
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/letsencrypt:ro
    networks:
      - proxy-net

'''
        compose += '''  certbot:
    image: certbot/dns-cloudflare
    container_name: certbot
    volumes:
      - ./certs:/etc/letsencrypt
      - ./cloudflare.ini:/etc/cloudflare/credentials.ini:ro
    profiles:
      - certbot

'''
        if cf_enabled:
            compose += '''  ddns-updater:
    image: alpine:latest
    container_name: ddns-updater
    restart: unless-stopped
    network_mode: host
    env_file:
      - .env
    volumes:
      - ./ddns-script.sh:/ddns-script.sh:ro
      - ./logs:/var/log/ddns
    entrypoint: ["/bin/sh", "-c", "apk add --no-cache curl && while true; do /ddns-script.sh; sleep 300; done"]

'''

        compose += '''networks:
  proxy-net:
    driver: bridge
'''
        return compose

    def _generate_nas_nginx_conf(self) -> str:
        """Generate NAS nginx configuration"""
        services = self.config.get('services', [])
        backend = self.config['backend']

        if not services:
            return "# No services configured\n"

        first_domain = services[0]['domain']

        # Generate per-service HTTPS server blocks for IPv6 direct access
        https_server_blocks = ""
        for service in services:
            name = service['name']
            domain = service['domain']

            # For services with local_backend, use that; otherwise use host.docker.internal
            if service.get('local_backend'):
                proxy_target = f"http://{service['local_backend']}"
            else:
                port = service['backend_port']
                proxy_target = f"http://host.docker.internal:{port}"

            websocket = service.get('websocket', False)
            host_header = service.get('host_header', 'frontend')
            timeout = service.get('timeout', {'connect': 60, 'send': 60, 'read': 60})

            https_server_blocks += f'''
    # {name.upper()} - IPv6 direct access
    server {{
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name {domain};

        location / {{
            proxy_pass {proxy_target};

'''
            if host_header == 'backend':
                backend_host = service.get('local_backend', f"host.docker.internal:{service['backend_port']}")
                https_server_blocks += f'            proxy_set_header Host {backend_host};\n'
            else:
                https_server_blocks += '            proxy_set_header Host $host;\n'

            https_server_blocks += '''            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            proxy_http_version 1.1;
'''
            if websocket:
                https_server_blocks += '''            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
'''
            else:
                https_server_blocks += '            proxy_set_header Connection "";\n'

            https_server_blocks += f'''
            proxy_connect_timeout {timeout.get('connect', 60)}s;
            proxy_send_timeout {timeout.get('send', 60)}s;
            proxy_read_timeout {timeout.get('read', 60)}s;

            proxy_buffering off;
            proxy_request_buffering off;
        }}
    }}
'''

        # Generate HTTP server blocks for services with local_backend (for VPS relay)
        http_relay_blocks = ""
        for service in services:
            if service.get('local_backend'):
                port = service['backend_port']
                local_backend = service['local_backend']
                websocket = service.get('websocket', False)
                host_header = service.get('host_header', 'frontend')
                timeout = service.get('timeout', {'connect': 60, 'send': 60, 'read': 60})

                http_relay_blocks += f'''
    # HTTP relay for {service['name']} (VPS -> NAS -> local backend)
    server {{
        listen {port};
        listen [::]:{port};
        server_name _;

        location / {{
            proxy_pass http://{local_backend};

'''
                if host_header == 'backend':
                    http_relay_blocks += f'            proxy_set_header Host {local_backend};\n'
                else:
                    http_relay_blocks += '            proxy_set_header Host $host;\n'

                http_relay_blocks += '''            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            proxy_http_version 1.1;
'''
                if websocket:
                    http_relay_blocks += '''            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
'''
                else:
                    http_relay_blocks += '            proxy_set_header Connection "";\n'

                http_relay_blocks += f'''
            proxy_connect_timeout {timeout.get('connect', 60)}s;
            proxy_send_timeout {timeout.get('send', 60)}s;
            proxy_read_timeout {timeout.get('read', 60)}s;

            proxy_buffering off;
            proxy_request_buffering off;
        }}
    }}
'''

        # Generate stream blocks for TCP services with local_backend
        tcp_services = self.config.get('tcp_services', [])
        stream_blocks = ""
        for tcp_svc in tcp_services:
            if tcp_svc.get('local_backend'):
                port = tcp_svc['backend_port']
                local_backend = tcp_svc['local_backend']
                name = tcp_svc['name']

                stream_blocks += f'''
# TCP relay for {name} (VPS -> NAS -> local backend)
stream {{
    server {{
        listen {port};
        listen [::]:{port};
        proxy_pass {local_backend};
        proxy_connect_timeout 60s;
        proxy_timeout 300s;
    }}
}}
'''

        return f'''# NAS Nginx Configuration for IPv6 Direct Access
# Auto-generated by relay46 deployer

user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;

events {{
    worker_connections 1024;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/rss+xml application/atom+xml image/svg+xml;

    # Shared SSL settings
    ssl_certificate /etc/letsencrypt/live/{first_domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{first_domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    map $http_upgrade $connection_upgrade {{
        default upgrade;
        ''      close;
    }}
{https_server_blocks}{http_relay_blocks}}}
{stream_blocks}'''

    def _generate_nas_ddns_script(self) -> str:
        """Generate DDNS update script for NAS"""
        return '''#!/bin/sh
# Cloudflare DDNS Update Script for NAS IPv6
# Auto-generated by relay46 deployer

LOG_FILE="/var/log/ddns/ddns.log"
IP_CACHE_FILE="/tmp/cloudflare-ddns-ipv6.cache"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

get_current_ipv6() {
    curl -6 -s --connect-timeout 10 ifconfig.me 2>/dev/null || \\
    curl -6 -s --connect-timeout 10 icanhazip.com 2>/dev/null || \\
    curl -6 -s --connect-timeout 10 ipv6.ip.sb 2>/dev/null
}

get_cached_ipv6() {
    if [ -f "$IP_CACHE_FILE" ]; then
        cat "$IP_CACHE_FILE"
    fi
}

update_dns_record() {
    local domain="$1"
    local ipv6="$2"

    local response=$(curl -s -X GET \\
        "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?type=AAAA&name=$domain" \\
        -H "Authorization: Bearer $CF_API_TOKEN" \\
        -H "Content-Type: application/json")

    local record_id=$(echo "$response" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -n "$record_id" ]; then
        local update_response=$(curl -s -X PUT \\
            "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$record_id" \\
            -H "Authorization: Bearer $CF_API_TOKEN" \\
            -H "Content-Type: application/json" \\
            --data '{"type":"AAAA","name":"'$domain'","content":"'$ipv6'","proxied":'$PROXIED',"ttl":1}')

        if echo "$update_response" | grep -q '"success":true'; then
            log "Updated $domain AAAA -> $ipv6"
            return 0
        else
            log "Failed to update $domain: $update_response"
            return 1
        fi
    else
        local create_response=$(curl -s -X POST \\
            "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \\
            -H "Authorization: Bearer $CF_API_TOKEN" \\
            -H "Content-Type: application/json" \\
            --data '{"type":"AAAA","name":"'$domain'","content":"'$ipv6'","proxied":'$PROXIED',"ttl":1}')

        if echo "$create_response" | grep -q '"success":true'; then
            log "Created $domain AAAA -> $ipv6"
            return 0
        else
            log "Failed to create $domain: $create_response"
            return 1
        fi
    fi
}

main() {
    mkdir -p "$(dirname "$LOG_FILE")"

    local current_ipv6=$(get_current_ipv6)

    if [ -z "$current_ipv6" ]; then
        log "ERROR: Failed to get current IPv6 address"
        exit 1
    fi

    local cached_ipv6=$(get_cached_ipv6)

    if [ "$current_ipv6" = "$cached_ipv6" ]; then
        exit 0
    fi

    log "IPv6 changed: $cached_ipv6 -> $current_ipv6"

    local success=true
    for domain in $DOMAINS; do
        if ! update_dns_record "$domain" "$current_ipv6"; then
            success=false
        fi
    done

    if [ "$success" = true ]; then
        echo "$current_ipv6" > "$IP_CACHE_FILE"
    fi
}

main "$@"
'''

    def _generate_nas_env_file(self) -> str:
        """Generate .env file for NAS DDNS"""
        cf_config = self.config.get('cloudflare', {})
        services = self.config.get('services', [])
        backend = self.config['backend']['host']

        domains = [s['domain'] for s in services]
        if backend not in domains:
            domains.append(backend)

        return f'''# Cloudflare DDNS Configuration
CF_API_TOKEN={cf_config.get('api_token', '')}
CF_ZONE_ID={cf_config.get('zone_id', '')}
DOMAINS={' '.join(domains)}
PROXIED={'true' if cf_config.get('proxied', False) else 'false'}
'''

    def _generate_nas_cloudflare_ini(self) -> str:
        """Generate Cloudflare credentials file for certbot DNS-01"""
        cf_config = self.config.get('cloudflare', {})
        return f"dns_cloudflare_api_token = {cf_config.get('api_token', '')}\n"

    # =========================================================================
    # Deployment Functions
    # =========================================================================

    def test_connection(self, target: str = "server") -> bool:
        """Test SSH connection"""
        cfg = self.config['server'] if target == "server" else self.config.get('nas', {})
        host = cfg.get('host', 'unknown')
        print(f"Testing connection to {host}...")

        code, stdout, stderr = self._ssh_cmd("echo 'Connection OK' && uname -a", target=target)

        if code == 0:
            print(f"  Connection successful")
            return True
        else:
            print(f"  Connection failed: {stderr}")
            return False

    def check_docker_installed(self, target: str = "server") -> bool:
        """Check if Docker and Docker Compose are installed"""
        code, stdout, stderr = self._ssh_cmd("docker --version && docker compose version", target=target)
        return code == 0

    def install_docker(self, target: str = "server") -> bool:
        """Install Docker on the target"""
        print("Installing Docker...")

        commands = [
            "curl -fsSL https://get.docker.com | sh",
            "systemctl enable docker",
            "systemctl start docker"
        ]

        for cmd in commands:
            code, stdout, stderr = self._ssh_cmd(cmd, target=target, timeout=300)
            if code != 0:
                print(f"  Failed to install Docker: {stderr}")
                return False

        print("  Docker installed successfully")
        return True

    def check_certs_exist(self) -> bool:
        """Check if SSL certificates already exist on VPS"""
        services = self.config.get('services', [])
        if not services:
            return True

        domain = services[0]['domain']
        code, stdout, stderr = self._ssh_cmd(
            f"test -f {self.VPS_DEPLOY_PATH}/certs/live/{domain}/fullchain.pem && echo 'exists'"
        )
        return code == 0 and 'exists' in stdout

    def get_cert_domains(self) -> List[str]:
        """Get domains currently in the SSL certificate"""
        services = self.config.get('services', [])
        if not services:
            return []

        domain = services[0]['domain']
        code, stdout, stderr = self._ssh_cmd(
            f"openssl x509 -in {self.VPS_DEPLOY_PATH}/certs/live/{domain}/fullchain.pem "
            f"-noout -text 2>/dev/null | grep -oP '(?<=DNS:)[^,\\s]+' | sort -u"
        )
        if code == 0 and stdout.strip():
            return [d.strip() for d in stdout.strip().split('\n') if d.strip()]
        return []

    def _temp_remove_aaaa_records(self, domains: List[str]) -> Dict[str, str]:
        """Temporarily remove AAAA records for certificate request

        Returns a dict of domain -> ipv6 address for restoration
        """
        cf_config = self.config.get('cloudflare', {})
        if not cf_config.get('enabled', False):
            return {}

        zone_id = cf_config['zone_id']
        removed_records = {}

        for domain in domains:
            try:
                # Get the AAAA record
                endpoint = f"/zones/{zone_id}/dns_records?type=AAAA&name={domain}"
                result = self._cloudflare_api("GET", endpoint)

                if result.get('success') and result.get('result'):
                    record = result['result'][0]
                    record_id = record['id']
                    ipv6 = record['content']

                    # Delete the record
                    self._cloudflare_api("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
                    removed_records[domain] = ipv6
                    print(f"    Temporarily removed AAAA for {domain}")
            except RuntimeError as e:
                print(f"    Warning: Could not remove AAAA for {domain}: {e}")

        return removed_records

    def _restore_aaaa_records(self, removed_records: Dict[str, str]):
        """Restore AAAA records after certificate request"""
        cf_config = self.config.get('cloudflare', {})
        if not cf_config.get('enabled', False) or not removed_records:
            return

        zone_id = cf_config['zone_id']
        proxied = cf_config.get('proxied', False)

        for domain, ipv6 in removed_records.items():
            try:
                self._cloudflare_api("POST", f"/zones/{zone_id}/dns_records", {
                    "type": "AAAA", "name": domain, "content": ipv6, "proxied": proxied, "ttl": 1
                })
                print(f"    Restored AAAA for {domain}")
            except RuntimeError as e:
                print(f"    Warning: Could not restore AAAA for {domain}: {e}")

    def request_certificates(self, force_renew: bool = False) -> bool:
        """Request or renew SSL certificates with automatic AAAA record handling

        This method:
        1. Checks which domains need to be added to the certificate
        2. Temporarily removes AAAA records (to avoid Let's Encrypt IPv6 verification issues)
        3. Requests/renews the certificate
        4. Restores AAAA records
        """
        services = self.config.get('services', [])
        if not services:
            return True

        configured_domains = [s['domain'] for s in services]
        current_cert_domains = self.get_cert_domains() if not force_renew else []

        # Find domains that need to be added
        new_domains = [d for d in configured_domains if d not in current_cert_domains]

        if not new_domains and not force_renew:
            print("  All domains already in certificate")
            return True

        print(f"  Domains to certify: {', '.join(configured_domains)}")
        if new_domains:
            print(f"  New domains: {', '.join(new_domains)}")

        # Temporarily remove AAAA records for domains being certified
        # This prevents Let's Encrypt from using IPv6 which may fail
        print("  Preparing DNS for certificate request...")
        removed_records = self._temp_remove_aaaa_records(configured_domains)

        if removed_records:
            # Wait for DNS propagation
            # Let's Encrypt resolvers may cache AAAA records; 30s helps ensure removal is seen
            import time
            print("  Waiting for DNS propagation (30s)...")
            time.sleep(30)

        # Request certificate
        domains_arg = " ".join([f"-d {d}" for d in configured_domains])
        email = self.config['ssl']['email']

        cert_cmd = (
            f"cd {self.VPS_DEPLOY_PATH} && "
            f"docker compose run --rm certbot certonly --webroot "
            f"-w /var/www/certbot {domains_arg} --email {email} "
            f"--agree-tos --non-interactive --expand"
        )

        print("  Requesting SSL certificates...")
        code, stdout, stderr = self._ssh_cmd(cert_cmd, timeout=180)

        # Restore AAAA records regardless of success
        if removed_records:
            print("  Restoring DNS records...")
            self._restore_aaaa_records(removed_records)

        if code != 0:
            print(f"  Certificate request failed: {stderr}")
            return False

        print("  Certificates obtained successfully")
        return True

    def get_vps_ipv4(self) -> str:
        """Get VPS IPv4 address"""
        import re
        server_host = self.config['server']['host']
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'

        if re.match(ipv4_pattern, server_host):
            return server_host

        code, stdout, stderr = self._ssh_cmd("curl -4 -s --connect-timeout 10 ifconfig.me")
        if code == 0 and stdout.strip():
            ip = stdout.strip()
            if re.match(ipv4_pattern, ip):
                return ip

        raise RuntimeError(f"Failed to get VPS IPv4 address: {stderr}")

    def get_nas_ipv6(self) -> str:
        """Get NAS IPv6 address"""
        nas_config = self.config.get('nas', {})
        if nas_config.get('ipv6'):
            return nas_config['ipv6']

        nas_host = nas_config.get('host', self.config['backend']['host'])

        code, stdout, stderr = self._ssh_cmd(f"dig +short AAAA {nas_host} | head -1")
        if code == 0 and stdout.strip() and ':' in stdout.strip():
            return stdout.strip()

        code, stdout, stderr = self._ssh_cmd("curl -6 -s --connect-timeout 10 ifconfig.me", target="nas")
        if code == 0 and stdout.strip() and ':' in stdout.strip():
            return stdout.strip()

        raise RuntimeError(f"Failed to get NAS IPv6 address: {stderr}")

    def _cloudflare_api(self, method: str, endpoint: str, data: dict = None) -> dict:
        """Call Cloudflare API"""
        cf_config = self.config.get('cloudflare', {})
        api_token = cf_config.get('api_token', '')
        base_url = "https://api.cloudflare.com/client/v4"

        url = f"{base_url}{endpoint}"
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }

        request_data = json.dumps(data).encode('utf-8') if data else None
        req = urllib.request.Request(url, data=request_data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            raise RuntimeError(f"Cloudflare API error ({e.code}): {error_body}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Cloudflare API network error: {e.reason}")

    def update_cloudflare_dns(self) -> bool:
        """Update Cloudflare DNS records"""
        cf_config = self.config.get('cloudflare', {})

        if not cf_config.get('enabled', False):
            print("  Cloudflare DNS not enabled, skipping")
            return True

        if not cf_config.get('api_token') or not cf_config.get('zone_id'):
            print("  Cloudflare config incomplete, skipping")
            return True

        print("Updating Cloudflare DNS records...")

        try:
            vps_ipv4 = self.get_vps_ipv4()
            print(f"  VPS IPv4: {vps_ipv4}")
        except RuntimeError as e:
            print(f"  {e}")
            return False

        try:
            nas_ipv6 = self.get_nas_ipv6()
            print(f"  NAS IPv6: {nas_ipv6}")
        except RuntimeError as e:
            print(f"  {e}")
            return False

        zone_id = cf_config['zone_id']
        proxied = cf_config.get('proxied', False)

        services = self.config.get('services', [])
        for service in services:
            domain = service['domain']
            print(f"  Processing domain: {domain}")

            # Update A record
            try:
                endpoint = f"/zones/{zone_id}/dns_records?type=A&name={domain}"
                result = self._cloudflare_api("GET", endpoint)

                if result.get('success') and result.get('result'):
                    record = result['result'][0]
                    if record['content'] != vps_ipv4:
                        self._cloudflare_api("PUT", f"/zones/{zone_id}/dns_records/{record['id']}", {
                            "type": "A", "name": domain, "content": vps_ipv4, "proxied": proxied, "ttl": 1
                        })
                        print(f"    A record updated: {vps_ipv4}")
                    else:
                        print(f"    A record already up to date")
                else:
                    self._cloudflare_api("POST", f"/zones/{zone_id}/dns_records", {
                        "type": "A", "name": domain, "content": vps_ipv4, "proxied": proxied, "ttl": 1
                    })
                    print(f"    A record created: {vps_ipv4}")
            except RuntimeError as e:
                print(f"    A record failed: {e}")

            # Update AAAA record
            try:
                endpoint = f"/zones/{zone_id}/dns_records?type=AAAA&name={domain}"
                result = self._cloudflare_api("GET", endpoint)

                if result.get('success') and result.get('result'):
                    record = result['result'][0]
                    if record['content'] != nas_ipv6:
                        self._cloudflare_api("PUT", f"/zones/{zone_id}/dns_records/{record['id']}", {
                            "type": "AAAA", "name": domain, "content": nas_ipv6, "proxied": proxied, "ttl": 1
                        })
                        print(f"    AAAA record updated: {nas_ipv6}")
                    else:
                        print(f"    AAAA record already up to date")
                else:
                    self._cloudflare_api("POST", f"/zones/{zone_id}/dns_records", {
                        "type": "AAAA", "name": domain, "content": nas_ipv6, "proxied": proxied, "ttl": 1
                    })
                    print(f"    AAAA record created: {nas_ipv6}")
            except RuntimeError as e:
                print(f"    AAAA record failed: {e}")

        return True

    def deploy_vps(self) -> bool:
        """Deploy Docker Compose setup to VPS"""
        print("Deploying to VPS...")

        # Create temp directory with all files
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create directory structure
            (tmppath / "nginx" / "conf.d").mkdir(parents=True)
            (tmppath / "nginx" / "stream.conf.d").mkdir(parents=True)
            (tmppath / "webroot" / ".well-known" / "acme-challenge").mkdir(parents=True)

            # Generate files
            (tmppath / "docker-compose.yaml").write_text(self._generate_vps_docker_compose())
            (tmppath / "nginx" / "nginx.conf").write_text(self._generate_vps_nginx_main_conf())
            (tmppath / "nginx" / "stream.conf.d" / "tcp_proxy.conf").write_text(self._generate_vps_stream_conf())
            (tmppath / "sync-cert-to-nas.sh").write_text(self._generate_vps_sync_script())

            # Check if certs exist
            certs_exist = self.check_certs_exist()

            if certs_exist:
                # Deploy with full SSL config
                (tmppath / "nginx" / "conf.d" / "nas_proxy.conf").write_text(
                    self._generate_vps_http_proxy_conf(with_ssl=True)
                )
            else:
                # Deploy with temporary config for cert request
                (tmppath / "nginx" / "conf.d" / "nas_proxy.conf").write_text(
                    self._generate_vps_http_proxy_conf(with_ssl=False)
                )

            # Create remote directory
            self._ssh_cmd(f"mkdir -p {self.VPS_DEPLOY_PATH}")

            # Upload files
            print("  Uploading configuration files...")
            code, _, stderr = self._scp_dir(str(tmppath) + "/.", self.VPS_DEPLOY_PATH)
            if code != 0:
                print(f"  Failed to upload files: {stderr}")
                return False

            # Make sync script executable
            self._ssh_cmd(f"chmod +x {self.VPS_DEPLOY_PATH}/sync-cert-to-nas.sh")

        # Configure firewall
        print("  Configuring firewall...")
        tcp_services = self.config.get('tcp_services', [])
        server_cfg = self.config.get('server', {})
        http_port = int(server_cfg.get('http_port', 80))
        https_port = int(server_cfg.get('https_port', 443))
        ufw_ports = {http_port, https_port}
        ufw_commands = [f"ufw allow {p}/tcp" for p in sorted(ufw_ports)]
        for svc in tcp_services:
            ufw_commands.append(f"ufw allow {svc['listen_port']}/tcp")
        ufw_commands.extend(["ufw --force enable", "ufw reload"])
        self._ssh_cmd(" && ".join(ufw_commands))

        # Start containers
        print("  Starting Docker containers...")
        code, stdout, stderr = self._ssh_cmd(
            f"cd {self.VPS_DEPLOY_PATH} && docker compose up -d nginx-proxy",
            timeout=180
        )
        if code != 0:
            print(f"  Failed to start containers: {stderr}")
            return False

        # Reload nginx to apply latest config (ports, hosts, etc.)
        self._ssh_cmd(f"cd {self.VPS_DEPLOY_PATH} && docker compose exec -T nginx-proxy nginx -s reload")

        # Request certificates if needed (new certs or new domains)
        services = self.config.get('services', [])
        configured_domains = [s['domain'] for s in services]
        current_cert_domains = self.get_cert_domains() if certs_exist else []
        needs_cert_update = not certs_exist or any(d not in current_cert_domains for d in configured_domains)

        if needs_cert_update and services:
            if not self.request_certificates():
                print("  Certificate request failed")
                print("  Ensure DNS records are correctly configured")
                return False

            # Update nginx config with SSL
            with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
                f.write(self._generate_vps_http_proxy_conf(with_ssl=True))
                temp_conf = f.name

            self._scp_file(temp_conf, f"{self.VPS_DEPLOY_PATH}/nginx/conf.d/nas_proxy.conf")
            os.unlink(temp_conf)

            # Reload nginx
            self._ssh_cmd(f"cd {self.VPS_DEPLOY_PATH} && docker compose exec nginx-proxy nginx -s reload")

        print("  VPS deployment complete")
        return True

    def request_nas_certificates(self) -> bool:
        """Request SSL certificates on NAS via DNS-01 challenge"""
        services = self.config.get('services', [])
        if not services:
            return True

        nas_config = self.config.get('nas', {})
        nas_deploy_path = nas_config.get('deploy_path', self.NAS_DEPLOY_PATH_DEFAULT)

        # Check if certs already exist
        domain = services[0]['domain']
        code, stdout, _ = self._ssh_cmd(
            f"test -f {nas_deploy_path}/certs/live/{domain}/fullchain.pem && echo 'exists'",
            target="nas"
        )
        if code == 0 and 'exists' in stdout:
            print("  NAS certificates already exist")
            return True

        # Build certbot command
        domains_arg = " ".join([f"-d {s['domain']}" for s in services])
        email = self.config['ssl']['email']

        cert_cmd = (
            f"cd {nas_deploy_path} && "
            f"docker compose run --rm certbot certonly "
            f"--dns-cloudflare "
            f"--dns-cloudflare-credentials /etc/cloudflare/credentials.ini "
            f"--dns-cloudflare-propagation-seconds 30 "
            f"{domains_arg} --email {email} "
            f"--agree-tos --non-interactive --expand"
        )

        print("  Requesting SSL certificates via DNS-01...")
        code, stdout, stderr = self._ssh_cmd(cert_cmd, target="nas", timeout=300)

        if code != 0:
            print(f"  Certificate request failed: {stderr}")
            return False

        print("  Certificates obtained successfully")
        return True

    def deploy_nas(self) -> bool:
        """Deploy Docker Compose setup to NAS"""
        nas_config = self.config.get('nas')
        if not nas_config:
            print("  No NAS configured, skipping")
            return True

        print("Deploying to NAS...")

        nas_deploy_path = nas_config.get('deploy_path', self.NAS_DEPLOY_PATH_DEFAULT)

        # Create temp directory with all files
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create directory structure
            (tmppath / "nginx").mkdir(parents=True)
            (tmppath / "certs").mkdir(parents=True)
            (tmppath / "logs").mkdir(parents=True)

            # Generate files
            (tmppath / "docker-compose.yaml").write_text(self._generate_nas_docker_compose())
            (tmppath / "nginx" / "nginx.conf").write_text(self._generate_nas_nginx_conf())

            # Cloudflare credentials for certbot DNS-01
            (tmppath / "cloudflare.ini").write_text(self._generate_nas_cloudflare_ini())

            cf_config = self.config.get('cloudflare', {})
            if cf_config.get('enabled', False):
                (tmppath / "ddns-script.sh").write_text(self._generate_nas_ddns_script())
                (tmppath / ".env").write_text(self._generate_nas_env_file())

            # Create remote directory
            self._ssh_cmd(f"mkdir -p {nas_deploy_path}", target="nas")

            # Upload files
            print("  Uploading configuration files...")
            code, _, stderr = self._scp_dir(str(tmppath) + "/.", nas_deploy_path, target="nas")
            if code != 0:
                print(f"  Failed to upload files: {stderr}")
                return False

            # Set file permissions
            if cf_config.get('enabled', False):
                self._ssh_cmd(f"chmod +x {nas_deploy_path}/ddns-script.sh", target="nas")
            self._ssh_cmd(f"chmod 600 {nas_deploy_path}/cloudflare.ini", target="nas")

        # Request certificates on NAS via DNS-01
        print("  Requesting SSL certificates...")
        if not self.request_nas_certificates():
            print("  Warning: Certificate request failed, NAS nginx may not start properly")

        # Start containers
        print("  Starting Docker containers...")
        code, stdout, stderr = self._ssh_cmd(
            f"cd {nas_deploy_path} && docker compose up -d",
            target="nas",
            timeout=180
        )
        if code != 0:
            print(f"  Failed to start containers: {stderr}")
            return False

        print("  NAS deployment complete")
        return True

    def setup_cron(self) -> bool:
        """Setup cron jobs for certificate renewal on VPS and NAS"""
        print("Setting up certificate renewal cron jobs...")

        # VPS cron (certbot webroot renewal only, no NAS sync)
        vps_cron_entry = f'0 0,12 * * * cd {self.VPS_DEPLOY_PATH} && docker compose run --rm certbot renew --webroot -w /var/www/certbot && docker compose exec nginx-proxy nginx -s reload >> /var/log/cert-renewal.log 2>&1'

        cron_cmd = f'(crontab -l 2>/dev/null | grep -v "relay46"; echo "{vps_cron_entry}") | crontab -'
        code, _, stderr = self._ssh_cmd(cron_cmd)

        if code != 0:
            print(f"  Failed to setup VPS cron: {stderr}")
            return False
        print("  VPS cron configured")

        # NAS cron (certbot DNS-01 renewal)
        nas_config = self.config.get('nas')
        if nas_config:
            nas_deploy_path = nas_config.get('deploy_path', self.NAS_DEPLOY_PATH_DEFAULT)
            nas_cron_entry = f'0 0,12 * * * cd {nas_deploy_path} && docker compose run --rm certbot renew && docker compose exec -T nginx-proxy nginx -s reload >> /var/log/cert-renewal.log 2>&1  # relay46-cert-renew'

            nas_cron_cmd = f'(crontab -l 2>/dev/null | grep -v "relay46-cert-renew"; echo "{nas_cron_entry}") | crontab -'
            code, _, stderr = self._ssh_cmd(nas_cron_cmd, target="nas")

            if code != 0:
                print(f"  Failed to setup NAS cron: {stderr}")
            else:
                print("  NAS cron configured")

        print("  Cron jobs configured (runs twice daily)")
        return True

    def verify_deployment(self) -> bool:
        """Verify deployment"""
        print("Verifying deployment...")

        # Check VPS containers
        code, stdout, _ = self._ssh_cmd(f"cd {self.VPS_DEPLOY_PATH} && docker compose ps --format json")
        if code == 0:
            print("  VPS containers running")
        else:
            print("  VPS containers not running properly")

        # Check NAS containers if configured
        nas_config = self.config.get('nas')
        if nas_config:
            nas_deploy_path = nas_config.get('deploy_path', self.NAS_DEPLOY_PATH_DEFAULT)
            code, stdout, _ = self._ssh_cmd(f"cd {nas_deploy_path} && docker compose ps --format json", target="nas")
            if code == 0:
                print("  NAS containers running")
            else:
                print("  NAS containers not running properly")

        return True

    def print_summary(self):
        """Print deployment summary"""
        print("\n" + "=" * 50)
        print("Deployment Complete!")
        print("=" * 50)

        services = self.config.get('services', [])
        tcp_services = self.config.get('tcp_services', [])
        nas_config = self.config.get('nas')

        if services:
            server_cfg = self.config.get('server', {})
            https_port = int(server_cfg.get('https_port', 443))
            https_port_suffix = "" if https_port == 443 else f":{https_port}"
            print("\nHTTP/HTTPS Services:")
            for service in services:
                print(f"  - {service['name']}: https://{service['domain']}{https_port_suffix}")

        if tcp_services:
            print("\nTCP Services:")
            server_host = self.config['server']['host']
            for svc in tcp_services:
                print(f"  - {svc['name']}: {server_host}:{svc['listen_port']}")

        print(f"\nVPS Configuration: {self.VPS_DEPLOY_PATH}/")
        if nas_config:
            nas_deploy_path = nas_config.get('deploy_path', self.NAS_DEPLOY_PATH_DEFAULT)
            print(f"NAS Configuration: {nas_deploy_path}/")

        print("\nUseful Commands:")
        print(f"  # VPS: Check status")
        print(f"  ssh vps 'cd {self.VPS_DEPLOY_PATH} && docker compose ps'")
        print(f"  # VPS: View logs")
        print(f"  ssh vps 'cd {self.VPS_DEPLOY_PATH} && docker compose logs -f'")
        if nas_config:
            nas_deploy_path = nas_config.get('deploy_path', self.NAS_DEPLOY_PATH_DEFAULT)
            print(f"  # NAS: Check status")
            print(f"  ssh nas 'cd {nas_deploy_path} && docker compose ps'")

    def deploy(self) -> bool:
        """Execute full deployment"""
        services = self.config.get('services', [])
        tcp_services = self.config.get('tcp_services', [])
        cf_enabled = self.config.get('cloudflare', {}).get('enabled', False)
        nas_config = self.config.get('nas')

        total_steps = 5  # connection, docker check, vps deploy, verify, cron
        if cf_enabled:
            total_steps += 1
        if nas_config:
            total_steps += 1

        print("\n" + "=" * 50)
        print("Relay46 Docker Compose Deployment")
        print("=" * 50)
        print(f"VPS: {self.config['server']['host']}")
        print(f"Backend: {self.config['backend']['host']}")
        print(f"HTTP Services: {len(services)}, TCP Services: {len(tcp_services)}")
        if cf_enabled:
            print("Cloudflare DNS: Enabled")

        current_step = 0

        # Step 1: Test connection
        current_step += 1
        self._print_step(current_step, total_steps, "Testing SSH Connection")
        if not self.test_connection():
            return False

        # Step 2: Check/Install Docker
        current_step += 1
        self._print_step(current_step, total_steps, "Checking Docker Installation")
        if not self.check_docker_installed():
            print("  Docker not found, installing...")
            if not self.install_docker():
                return False
        else:
            print("  Docker is installed")

        # Step 3: Update Cloudflare DNS
        if cf_enabled:
            current_step += 1
            self._print_step(current_step, total_steps, "Updating Cloudflare DNS")
            self.update_cloudflare_dns()

        # Step 4: Deploy VPS
        current_step += 1
        self._print_step(current_step, total_steps, "Deploying VPS")
        if not self.deploy_vps():
            return False

        # Step 5: Deploy NAS
        if nas_config:
            current_step += 1
            self._print_step(current_step, total_steps, "Deploying NAS")
            if not self.deploy_nas():
                return False

        # Step 6: Setup cron
        current_step += 1
        self._print_step(current_step, total_steps, "Setting Up Certificate Renewal")
        self.setup_cron()

        # Step 7: Verify
        current_step += 1
        self._print_step(current_step, total_steps, "Verifying Deployment")
        self.verify_deployment()

        self.print_summary()
        return True


def main():
    script_dir = Path(__file__).parent.resolve()
    os.chdir(script_dir)

    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"

    deployer = Relay46Deployer(config_path)
    success = deployer.deploy()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
