# Relay46 - Nginx IPv6 反向代理一键部署

将 VPS (双栈) 配置为家庭 NAS (仅 IPv6) 的反向代理。

## 快速开始

```bash
# 1. 编辑配置文件
vim config.yaml

# 2. 运行部署脚本
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

编辑 `config.yaml`:

```yaml
# 远程服务器
server:
  host: "你的VPS IP"
  port: 22
  user: "root"
  password: "你的密码"

# SSL 证书邮箱
ssl:
  email: "your@email.com"

# 后端 NAS (IPv6 DDNS 域名)
backend:
  host: "nas.example.com"

# 代理服务列表
services:
  - name: "服务名称"
    domain: "外部域名"
    backend_port: 端口号
    websocket: true/false    # 是否启用 WebSocket
    host_header: "frontend"  # frontend 或 backend
```

## 添加新服务

在 `services` 列表中添加新条目:

```yaml
services:
  # ... 现有服务 ...

  - name: "jellyfin"
    domain: "media.example.com"
    backend_port: 8096
    websocket: true
    host_header: "frontend"
    timeout:
      connect: 60
      send: 60
      read: 60
```

然后重新运行 `python3 deploy.py`。

## 文件结构

```
relay46/
├── config.yaml    # 配置文件
├── deploy.py      # 部署脚本
└── README.md      # 说明文档
```

## 部署后的远程文件

- `/etc/nginx/conf.d/nas_proxy.conf` - 主配置
- `/etc/nginx/conf.d/websocket_map.conf` - WebSocket 映射
- `/etc/letsencrypt/live/*/` - SSL 证书

## 常用维护命令 (在 VPS 上执行)

```bash
# 测试配置
nginx -t

# 重载配置
systemctl reload nginx

# 续期证书
certbot renew

# 查看错误日志
tail -f /var/log/nginx/error.log
```

## 注意事项

1. 运行前确保域名 DNS 已解析到 VPS IP
2. 确保 VPS 支持 IPv6 出站连接
3. 证书会自动续期 (certbot timer)
