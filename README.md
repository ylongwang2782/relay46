# Relay46 - Nginx IPv6 反向代理一键部署

将 VPS (双栈) 配置为家庭 NAS (仅 IPv6) 的反向代理，支持 HTTP/HTTPS 和 TCP 流代理。

## 功能

- **HTTP/HTTPS 反向代理**: 支持 WebSocket、自动 SSL 证书
- **TCP 流代理**: SSH、数据库等任意 TCP 服务中转
- **IPv6 支持**: 动态解析后端 IPv6 DDNS 域名
- **证书自动同步**: 续期后自动同步到 NAS
- **SSH 密钥认证**: 安全，无需明文密码

## 快速开始

```bash
# 1. 克隆仓库
git clone https://github.com/ylongwang2782/relay46.git
cd relay46

# 2. 配置 SSH 密钥认证
ssh-copy-id root@YOUR_VPS_IP
ssh-copy-id user@YOUR_NAS_HOST

# 3. 创建配置文件
cp config.example.yaml config.yaml
vim config.yaml

# 4. 运行部署
python3 deploy.py
```

## 依赖

- Python 3.6+
- SSH 密钥认证 (无需 sshpass)

```bash
pip3 install pyyaml
```

## 配置说明

### SSH 密钥认证 (推荐)

```yaml
server:
  host: "YOUR_VPS_IP"
  user: "root"
  # identity_file: "~/.ssh/id_ed25519"  # 可选

nas:
  host: "nas.example.com"
  user: "your_user"
```

### HTTP/HTTPS 服务

```yaml
services:
  - name: "web-panel"
    domain: "panel.example.com"
    backend_port: 5666
    websocket: true
    host_header: "frontend"
```

### TCP 服务 (SSH 等)

```yaml
tcp_services:
  - name: "ssh"
    listen_port: 2222
    backend_port: 22
    protocol: "tcp"
```

## 文件结构

```
relay46/
├── config.yaml         # 配置文件 (不提交)
├── config.example.yaml # 配置模板
├── deploy.py           # 部署脚本
└── README.md
```

## SSH Config 示例

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

## 常用命令

```bash
# 部署
python3 deploy.py

# SSH 到 NAS (通过 VPS 代理)
ssh nas

# VPS 上的维护命令
ssh vps "nginx -t && systemctl reload nginx"
ssh vps "certbot renew"
```

## 注意事项

1. 部署前确保 SSH 密钥认证已配置
2. 域名 DNS 需正确解析到 VPS IP
3. 证书续期后会自动同步到 NAS
4. config.yaml 包含敏感信息，已在 .gitignore 中排除
