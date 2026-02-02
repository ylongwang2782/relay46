# Relay46 - Nginx IPv6 反向代理一键部署

将 VPS (双栈) 配置为家庭 NAS (仅 IPv6) 的反向代理，支持 HTTP/HTTPS 和 TCP 流代理。

## 功能

- **HTTP/HTTPS 反向代理**: 支持 WebSocket、自动 SSL 证书
- **TCP 流代理**: SSH、数据库等任意 TCP 服务中转
- **IPv6 支持**: 动态解析后端 IPv6 DDNS 域名
- **一键部署**: 自动安装、配置、申请证书

## 快速开始

```bash
# 1. 克隆仓库
git clone https://github.com/ylongwang2782/relay46.git
cd relay46

# 2. 创建配置文件
cp config.example.yaml config.yaml
vim config.yaml

# 3. 运行部署
python3 deploy.py
```

## 依赖

- Python 3.6+
- sshpass

### macOS
```bash
brew install sshpass
pip3 install pyyaml
```

### Ubuntu/Debian
```bash
apt install sshpass python3-yaml
```

## 配置说明

### 服务器配置

```yaml
server:
  host: "你的VPS IP"
  port: 22
  user: "root"
  password: "你的密码"
```

### HTTP/HTTPS 服务

```yaml
services:
  - name: "web-panel"
    domain: "panel.example.com"  # 外部访问域名
    backend_port: 5666           # 后端端口
    websocket: true              # WebSocket 支持
    host_header: "frontend"      # frontend 或 backend
```

### TCP 服务 (SSH 等)

```yaml
tcp_services:
  - name: "ssh"
    listen_port: 2222    # VPS 监听端口
    backend_port: 22     # 后端 NAS 端口
    protocol: "tcp"
```

部署后可通过以下方式 SSH 到 NAS:

```bash
ssh -p 2222 user@你的VPS_IP
```

## 添加新服务

编辑 `config.yaml`，在对应列表中添加新条目，然后重新运行 `python3 deploy.py`。

## 文件结构

```
relay46/
├── config.yaml         # 配置文件 (包含敏感信息，不提交)
├── config.example.yaml # 配置模板
├── deploy.py           # 部署脚本
└── README.md           # 说明文档
```

## 部署后的远程文件

| 文件 | 说明 |
|------|------|
| `/etc/nginx/conf.d/nas_proxy.conf` | HTTP 反向代理配置 |
| `/etc/nginx/conf.d/websocket_map.conf` | WebSocket 映射 |
| `/etc/nginx/stream.conf.d/tcp_proxy.conf` | TCP 流代理配置 |
| `/etc/letsencrypt/live/*/` | SSL 证书 |

## 常用维护命令

```bash
# 在 VPS 上执行
nginx -t                          # 测试配置
systemctl reload nginx            # 重载配置
certbot renew                     # 续期证书
tail -f /var/log/nginx/error.log  # 查看错误日志
ss -tlnp | grep nginx             # 查看监听端口
```

## 注意事项

1. 运行前确保域名 DNS 已解析到 VPS IP
2. 确保 VPS 支持 IPv6 出站连接
3. SSL 证书会自动续期 (certbot timer)
4. TCP 代理端口需避免与 VPS 本身服务冲突
