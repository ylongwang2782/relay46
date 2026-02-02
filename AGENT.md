# Relay46 项目说明

## 项目概述

Relay46 是一个 Nginx 反向代理一键部署工具，用于将 VPS（双栈）配置为家庭 NAS（仅 IPv6）的流量中转站。

## 核心功能

1. **HTTP/HTTPS 反向代理** - 支持 WebSocket，自动申请 Let's Encrypt 证书
2. **TCP 流代理** - 使用 Nginx stream 模块转发 SSH、数据库等 TCP 服务
3. **证书自动同步** - VPS 证书续期后自动同步到 NAS
4. **IPv4/IPv6 双栈支持** - IPv4 走 VPS 反代，IPv6 可直连 NAS

## 架构

```
IPv4 用户 → fnos.ylongwang.top:443 → VPS Nginx → NAS:5666 (HTTP)
IPv6 用户 → fnos.ylongwang.top:443 → NAS iptables → Docker Nginx:8443 → NAS:5666
SSH 用户  → VPS:2222 → NAS:22
```

## 文件结构

```
relay46/
├── deploy.py           # 主部署脚本 (Python)
├── config.yaml         # 用户配置文件 (含敏感信息，不提交)
├── config.example.yaml # 配置模板
├── README.md           # 用户文档
├── AGENT.md            # 项目说明 (本文件)
└── .gitignore          # 忽略 config.yaml 等
```

## 配置文件结构 (config.yaml)

```yaml
server:           # VPS SSH 配置
  host: "IP"
  port: 22
  user: "root"
  # identity_file: "~/.ssh/id_ed25519"  # 可选

nas:              # NAS SSH 配置 (用于证书同步)
  host: "nas-origin.example.com"
  user: "username"

ssl:              # Let's Encrypt 配置
  email: "admin@example.com"

backend:          # 后端 NAS 地址 (IPv6 DDNS)
  host: "nas-origin.example.com"

resolver:         # DNS 解析器
  servers: ["8.8.8.8", "8.8.4.4"]
  ipv6: true

services:         # HTTP/HTTPS 服务列表
  - name: "fnos"
    domain: "fnos.example.com"
    backend_port: 5666
    websocket: true
    host_header: "frontend"  # 或 "backend"

tcp_services:     # TCP 服务列表
  - name: "ssh"
    listen_port: 2222
    backend_port: 22
```

## 部署脚本功能 (deploy.py)

### 主要类: NginxProxyDeployer

- `test_connection()` - 测试 SSH 连接
- `install_packages()` - 安装 nginx, certbot, libnginx-mod-stream
- `configure_firewall()` - 配置 UFW 防火墙
- `deploy_nginx_config()` - 部署 HTTP 反向代理配置
- `deploy_stream_config()` - 部署 TCP stream 配置
- `request_certificates()` - 申请 Let's Encrypt 证书
- `setup_cert_sync()` - 配置证书同步到 NAS
- `verify_deployment()` - 验证部署结果

### SSH 命令执行

使用原生 SSH 密钥认证，无需 sshpass：
```python
def _ssh_cmd(self, command, target="server", timeout=120)
def _scp_cmd(self, local_path, remote_path, target="server")
```

## 远程服务器配置

### VPS 文件位置

- `/etc/nginx/conf.d/nas_proxy.conf` - HTTP 反向代理
- `/etc/nginx/conf.d/websocket_map.conf` - WebSocket 映射
- `/etc/nginx/stream.conf.d/tcp_proxy.conf` - TCP 流代理
- `/etc/letsencrypt/` - SSL 证书
- `/usr/local/bin/sync-cert-to-nas.sh` - 证书同步脚本
- `/etc/letsencrypt/renewal-hooks/deploy/sync-to-nas.sh` - certbot hook

### NAS 文件位置

- `~/nginx-proxy/conf/nginx.conf` - Docker Nginx 配置
- `~/nginx-proxy/certs/` - SSL 证书
- `/etc/iptables/ip6tables.rules` - iptables 规则
- `/etc/systemd/system/ip6tables-restore.service` - 规则恢复服务

## NAS Docker Nginx

用于 IPv6 直连时提供 HTTPS：

```bash
docker run -d \
  --name nginx-proxy \
  --restart unless-stopped \
  --add-host host.docker.internal:host-gateway \
  -p 8443:443 \
  -v ~/nginx-proxy/conf/nginx.conf:/etc/nginx/nginx.conf:ro \
  -v ~/nginx-proxy/certs:/etc/nginx/certs:ro \
  nginx:alpine
```

## IPv6 直连 443 端口实现

使用 iptables 将特定 IPv6 地址的 443 流量重定向到 8443：

```bash
ip6tables -t nat -A PREROUTING -d 2409:8a55:321c:3501::905 -p tcp --dport 443 -j REDIRECT --to-port 8443
```

## 本地 SSH 配置

```
# ~/.ssh/config

Host vps relay46
    HostName 108.61.219.138
    User root
    IdentityFile ~/.ssh/id_ed25519

Host nas fnos
    HostName 108.61.219.138
    Port 2222
    User ylongwang
    IdentityFile ~/.ssh/id_ed25519
```

## 常用命令

```bash
# 部署
python3 deploy.py

# 连接
ssh vps    # VPS
ssh nas    # NAS (通过 VPS 2222 端口)

# VPS 维护
ssh vps "nginx -t && systemctl reload nginx"
ssh vps "certbot renew"
ssh vps "/usr/local/bin/sync-cert-to-nas.sh"

# NAS 维护
ssh nas "docker logs nginx-proxy"
ssh nas "docker exec nginx-proxy nginx -s reload"
```

## 注意事项

1. 部署前需配置 SSH 密钥认证
2. config.yaml 包含敏感信息，已在 .gitignore 中排除
3. 域名 DNS 的 A 记录指向 VPS，AAAA 记录指向 NAS
4. fnOS 自带 Nginx 占用 443 端口，需用 iptables 重定向
5. 证书续期后会自动同步到 NAS 并重载 Docker Nginx
