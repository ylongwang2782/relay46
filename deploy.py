#!/usr/bin/env python3
"""
Nginx 反向代理一键部署脚本
用于将 VPS 配置为 IPv6 NAS 的反向代理

支持:
    - HTTP/HTTPS 反向代理 (WebSocket)
    - TCP 流代理 (SSH, 数据库等)
    - SSL 证书自动同步到 NAS

使用方法:
    1. 配置 SSH 密钥认证 (ssh-copy-id)
    2. 编辑 config.yaml 配置文件
    3. 运行: python3 deploy.py

依赖:
    - Python 3.6+
    - PyYAML: pip3 install pyyaml
    - SSH 密钥认证 (无需 sshpass)
"""

import subprocess
import sys
import os
from pathlib import Path

# 检查并安装 PyYAML
try:
    import yaml
except ImportError:
    print("正在安装 PyYAML...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])
    import yaml


class NginxProxyDeployer:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()

    def _load_config(self) -> dict:
        """加载 YAML 配置文件"""
        if not self.config_path.exists():
            print(f"错误: 配置文件 {self.config_path} 不存在")
            sys.exit(1)

        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def _build_ssh_cmd(self, target: str = "server") -> list:
        """构建 SSH 命令基础参数"""
        if target == "server":
            cfg = self.config['server']
        elif target == "nas":
            cfg = self.config.get('nas', {})
            if not cfg:
                cfg = {'host': self.config['backend']['host'], 'user': 'root'}
        else:
            raise ValueError(f"Unknown target: {target}")

        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
        ]

        if 'port' in cfg:
            cmd.extend(["-p", str(cfg['port'])])

        if 'identity_file' in cfg:
            identity = os.path.expanduser(cfg['identity_file'])
            cmd.extend(["-i", identity])

        cmd.append(f"{cfg['user']}@{cfg['host']}")
        return cmd

    def _ssh_cmd(self, command: str, target: str = "server", timeout: int = 120) -> tuple[int, str, str]:
        """执行远程 SSH 命令"""
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
            return -1, "", "命令执行超时"

    def _scp_cmd(self, local_path: str, remote_path: str, target: str = "server") -> tuple[int, str, str]:
        """SCP 文件到远程"""
        if target == "server":
            cfg = self.config['server']
        else:
            cfg = self.config.get('nas', {'host': self.config['backend']['host'], 'user': 'root'})

        cmd = ["scp", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes"]

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
            return -1, "", "SCP 超时"

    def _print_step(self, step: int, total: int, message: str):
        """打印步骤信息"""
        print(f"\n[{step}/{total}] {message}")
        print("=" * 50)

    def test_connection(self) -> bool:
        """测试 SSH 连接"""
        print(f"测试连接到 {self.config['server']['host']}...")
        code, stdout, stderr = self._ssh_cmd("echo 'Connection OK' && cat /etc/os-release | grep PRETTY_NAME")

        if code == 0:
            print(f"✓ 连接成功")
            for line in stdout.strip().split('\n'):
                if 'PRETTY_NAME' in line or 'Connection' in line:
                    print(f"  {line}")
            return True
        else:
            print(f"✗ 连接失败: {stderr}")
            print("  请确保已配置 SSH 密钥认证: ssh-copy-id user@host")
            return False

    def install_packages(self) -> bool:
        """安装 Nginx 和 Certbot"""
        print("安装 Nginx 和 Certbot...")

        commands = [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update -qq",
            "apt-get install -y -qq nginx certbot python3-certbot-nginx libnginx-mod-stream"
        ]

        code, stdout, stderr = self._ssh_cmd(" && ".join(commands), timeout=180)

        if code == 0:
            print("✓ 软件包安装完成")
            return True
        else:
            print(f"✗ 安装失败: {stderr}")
            return False

    def configure_firewall(self) -> bool:
        """配置防火墙"""
        print("配置防火墙...")

        commands = [
            "ufw allow 80/tcp",
            "ufw allow 443/tcp",
        ]

        tcp_services = self.config.get('tcp_services', [])
        for svc in tcp_services:
            port = svc['listen_port']
            commands.append(f"ufw allow {port}/tcp")

        commands.extend([
            "ufw --force enable",
            "ufw reload"
        ])

        code, stdout, stderr = self._ssh_cmd(" && ".join(commands))

        if code == 0:
            ports = "80/443"
            if tcp_services:
                ports += "/" + "/".join(str(s['listen_port']) for s in tcp_services)
            print(f"✓ 防火墙配置完成 (已开放 {ports} 端口)")
            return True
        else:
            print("⚠ 防火墙配置跳过 (可能未安装 UFW)")
            return True

    def _generate_nginx_config(self) -> str:
        """生成 Nginx 配置文件内容"""
        config = self.config
        resolver = config['resolver']
        backend = config['backend']
        services = config.get('services', [])

        if not services:
            return "# 无 HTTP 服务配置\n"

        resolver_servers = " ".join(resolver['servers'])
        resolver_ipv6 = "ipv6=on" if resolver.get('ipv6', True) else "ipv6=off"

        nginx_config = f'''# ===========================================
# NAS 反向代理配置 (自动生成)
# 后端: {backend['host']}
# ===========================================

resolver {resolver_servers} {resolver_ipv6} valid={resolver.get('valid', '300s')};
resolver_timeout {resolver.get('timeout', '5s')};

'''

        first_ssl_domain = services[0]['domain'] if services else None

        for i, service in enumerate(services):
            name = service['name']
            domain = service['domain']
            port = service['backend_port']
            websocket = service.get('websocket', False)
            host_header = service.get('host_header', 'frontend')
            timeout = service.get('timeout', {'connect': 60, 'send': 60, 'read': 60})

            ssl_domain = first_ssl_domain
            ipv6_ssl_listen = "listen [::]:443 ssl http2 ipv6only=on;" if i == 0 else "listen [::]:443 ssl http2;"

            nginx_config += f'''# =====================
# {name.upper()}
# =====================
server {{
    listen 80;
    listen [::]:80;
    server_name {domain};

    if ($host = {domain}) {{
        return 301 https://$host$request_uri;
    }}
    return 404;
}}

server {{
    listen 443 ssl http2;
    {ipv6_ssl_listen}
    server_name {domain};

    ssl_certificate /etc/letsencrypt/live/{ssl_domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{ssl_domain}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

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

    def _generate_websocket_map(self) -> str:
        """生成 WebSocket 映射配置"""
        return '''# WebSocket 连接升级映射
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
'''

    def _generate_stream_config(self) -> str:
        """生成 TCP stream 配置"""
        tcp_services = self.config.get('tcp_services', [])
        if not tcp_services:
            return ""

        backend = self.config['backend']['host']
        resolver = self.config['resolver']
        resolver_servers = " ".join(resolver['servers'])
        resolver_ipv6 = "ipv6=on" if resolver.get('ipv6', True) else "ipv6=off"

        stream_config = f'''# TCP 流代理配置 (自动生成)

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

    def deploy_nginx_config(self) -> bool:
        """部署 Nginx 配置文件"""
        print("生成并部署 Nginx 配置...")

        nginx_config = self._generate_nginx_config()
        websocket_map = self._generate_websocket_map()

        services = self.config.get('services', [])
        if services:
            temp_config = ""
            for service in services:
                domain = service['domain']
                temp_config += f'''server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    location / {{ return 200 "OK"; }}
}}
'''

            cmd = f"cat > /etc/nginx/conf.d/websocket_map.conf << 'EOFWS'\n{websocket_map}EOFWS"
            code, _, stderr = self._ssh_cmd(cmd)
            if code != 0:
                print(f"✗ WebSocket 映射配置失败: {stderr}")
                return False

            cmd = f"cat > /etc/nginx/conf.d/nas_proxy.conf << 'EOFTEMP'\n{temp_config}EOFTEMP"
            code, _, stderr = self._ssh_cmd(cmd)
            if code != 0:
                print(f"✗ 临时配置部署失败: {stderr}")
                return False

            code, _, stderr = self._ssh_cmd("nginx -t && systemctl reload nginx")
            if code != 0:
                print(f"✗ Nginx 配置测试失败: {stderr}")
                return False

            print("✓ HTTP 临时配置部署完成")

        self._full_nginx_config = nginx_config
        return True

    def deploy_stream_config(self) -> bool:
        """部署 TCP stream 配置"""
        tcp_services = self.config.get('tcp_services', [])
        if not tcp_services:
            print("⚠ 无 TCP 服务配置，跳过")
            return True

        print("部署 TCP stream 配置...")

        stream_config = self._generate_stream_config()

        code, _, _ = self._ssh_cmd("mkdir -p /etc/nginx/stream.conf.d")
        if code != 0:
            print("✗ 创建 stream 配置目录失败")
            return False

        cmd = f"cat > /etc/nginx/stream.conf.d/tcp_proxy.conf << 'EOFSTREAM'\n{stream_config}EOFSTREAM"
        code, _, stderr = self._ssh_cmd(cmd)
        if code != 0:
            print(f"✗ Stream 配置部署失败: {stderr}")
            return False

        code, stdout, _ = self._ssh_cmd("grep -c 'stream.conf.d' /etc/nginx/nginx.conf || echo '0'")
        if '0' in stdout:
            stream_include = '''
# TCP/UDP stream 代理
stream {
    include /etc/nginx/stream.conf.d/*.conf;
}
'''
            cmd = f"echo '{stream_include}' >> /etc/nginx/nginx.conf"
            code, _, stderr = self._ssh_cmd(cmd)
            if code != 0:
                print(f"✗ 添加 stream include 失败: {stderr}")
                return False

        code, _, stderr = self._ssh_cmd("nginx -t && systemctl reload nginx")
        if code != 0:
            print(f"✗ Nginx 配置测试失败: {stderr}")
            return False

        print("✓ TCP stream 配置部署完成")
        for svc in tcp_services:
            print(f"    - {svc['name']}: 端口 {svc['listen_port']} -> 后端 {svc['backend_port']}")

        return True

    def request_certificates(self) -> bool:
        """申请 SSL 证书"""
        services = self.config.get('services', [])
        if not services:
            print("⚠ 无 HTTP 服务，跳过 SSL 证书申请")
            return True

        print("申请 SSL 证书...")

        domains = [s['domain'] for s in services]
        domain_args = " ".join([f"-d {d}" for d in domains])
        email = self.config['ssl']['email']

        cmd = f"certbot --nginx {domain_args} --non-interactive --agree-tos --email {email} --redirect"
        code, stdout, stderr = self._ssh_cmd(cmd, timeout=180)

        if code == 0:
            print("✓ SSL 证书申请成功")
            return True
        else:
            print(f"✗ 证书申请失败: {stderr}")
            print("提示: 请确保域名 DNS 已正确解析到服务器 IP")
            return False

    def finalize_config(self) -> bool:
        """部署最终的反向代理配置"""
        services = self.config.get('services', [])
        if not services:
            print("⚠ 无 HTTP 服务配置")
            return True

        print("部署最终 HTTP 配置...")

        cmd = f"cat > /etc/nginx/conf.d/nas_proxy.conf << 'EOFFINAL'\n{self._full_nginx_config}EOFFINAL"
        code, _, stderr = self._ssh_cmd(cmd)
        if code != 0:
            print(f"✗ 配置部署失败: {stderr}")
            return False

        code, stdout, stderr = self._ssh_cmd("nginx -t && systemctl reload nginx")
        if code != 0:
            print(f"✗ Nginx 配置测试失败: {stderr}")
            return False

        print("✓ HTTP 配置部署完成")
        return True

    def setup_cert_sync(self) -> bool:
        """配置证书同步到 NAS"""
        nas_config = self.config.get('nas')
        if not nas_config:
            print("⚠ 未配置 NAS，跳过证书同步设置")
            return True

        print("配置证书同步...")

        services = self.config.get('services', [])
        if not services:
            return True

        domain = services[0]['domain']
        nas_host = nas_config['host']
        nas_user = nas_config['user']

        sync_script = f'''#!/bin/bash
# SSL 证书同步脚本 - 同步到 NAS Docker Nginx

DOMAIN="{domain}"
NAS_HOST="{nas_host}"
NAS_USER="{nas_user}"
CERT_DIR="/etc/letsencrypt/live/${{DOMAIN}}"
NAS_CERT_DIR="/home/${{NAS_USER}}/nginx-proxy/certs"

if [ ! -f "${{CERT_DIR}}/fullchain.pem" ]; then
    echo "错误: 证书不存在"
    exit 1
fi

echo "[$(date)] 同步证书到 NAS..."
scp ${{CERT_DIR}}/fullchain.pem ${{NAS_USER}}@${{NAS_HOST}}:${{NAS_CERT_DIR}}/fullchain.crt
scp ${{CERT_DIR}}/privkey.pem ${{NAS_USER}}@${{NAS_HOST}}:${{NAS_CERT_DIR}}/private.key
ssh ${{NAS_USER}}@${{NAS_HOST}} "docker exec nginx-proxy nginx -s reload 2>/dev/null || true"
echo "[$(date)] 同步完成!"
'''

        cmd = f"cat > /usr/local/bin/sync-cert-to-nas.sh << 'EOFSYNC'\n{sync_script}EOFSYNC"
        code, _, _ = self._ssh_cmd(cmd)
        if code != 0:
            print("⚠ 同步脚本创建失败")
            return True

        self._ssh_cmd("chmod +x /usr/local/bin/sync-cert-to-nas.sh")

        # 配置 deploy hook
        hook_script = '''#!/bin/bash
/usr/local/bin/sync-cert-to-nas.sh >> /var/log/cert-sync.log 2>&1
'''
        cmd = f"mkdir -p /etc/letsencrypt/renewal-hooks/deploy && cat > /etc/letsencrypt/renewal-hooks/deploy/sync-to-nas.sh << 'EOFHOOK'\n{hook_script}EOFHOOK"
        self._ssh_cmd(cmd)
        self._ssh_cmd("chmod +x /etc/letsencrypt/renewal-hooks/deploy/sync-to-nas.sh")

        print("✓ 证书同步配置完成")
        return True

    def verify_deployment(self) -> bool:
        """验证部署"""
        print("验证部署...")

        code, stdout, _ = self._ssh_cmd("systemctl is-active nginx")
        if code == 0 and "active" in stdout:
            print("✓ Nginx 运行正常")
        else:
            print("✗ Nginx 未运行")
            return False

        services = self.config.get('services', [])
        if services:
            code, stdout, _ = self._ssh_cmd("certbot certificates 2>/dev/null | grep -E 'Domains:|Expiry'")
            if code == 0:
                print("✓ SSL 证书状态:")
                for line in stdout.strip().split('\n'):
                    print(f"    {line.strip()}")

        tcp_services = self.config.get('tcp_services', [])
        if tcp_services:
            code, stdout, _ = self._ssh_cmd("ss -tlnp | grep nginx")
            for svc in tcp_services:
                port = svc['listen_port']
                if f":{port}" in stdout:
                    print(f"✓ TCP 端口 {port} ({svc['name']}) 监听正常")

        return True

    def print_summary(self):
        """打印部署总结"""
        print("\n" + "=" * 50)
        print("部署完成!")
        print("=" * 50)

        services = self.config.get('services', [])
        tcp_services = self.config.get('tcp_services', [])

        if services:
            print("\nHTTP/HTTPS 服务:")
            for service in services:
                print(f"  - {service['name']}: https://{service['domain']}")

        if tcp_services:
            print("\nTCP 服务:")
            server_host = self.config['server']['host']
            for svc in tcp_services:
                print(f"  - {svc['name']}: {server_host}:{svc['listen_port']}")

        print("\n配置文件位置 (远程服务器):")
        print("  - /etc/nginx/conf.d/nas_proxy.conf")
        if tcp_services:
            print("  - /etc/nginx/stream.conf.d/tcp_proxy.conf")

    def deploy(self):
        """执行完整部署"""
        services = self.config.get('services', [])
        tcp_services = self.config.get('tcp_services', [])

        total_steps = 4
        if services:
            total_steps += 4  # HTTP 配置、证书、最终配置、同步设置
        if tcp_services:
            total_steps += 1

        print("\n" + "=" * 50)
        print("Nginx 反向代理一键部署")
        print("=" * 50)
        print(f"目标服务器: {self.config['server']['host']}")
        print(f"后端地址: {self.config['backend']['host']}")
        print(f"HTTP 服务: {len(services)}, TCP 服务: {len(tcp_services)}")

        current_step = 0

        current_step += 1
        self._print_step(current_step, total_steps, "测试 SSH 连接")
        if not self.test_connection():
            return False

        current_step += 1
        self._print_step(current_step, total_steps, "安装软件包")
        if not self.install_packages():
            return False

        current_step += 1
        self._print_step(current_step, total_steps, "配置防火墙")
        if not self.configure_firewall():
            return False

        if services:
            current_step += 1
            self._print_step(current_step, total_steps, "部署 Nginx HTTP 配置")
            if not self.deploy_nginx_config():
                return False

            current_step += 1
            self._print_step(current_step, total_steps, "申请 SSL 证书")
            if not self.request_certificates():
                return False

            current_step += 1
            self._print_step(current_step, total_steps, "部署最终 HTTP 配置")
            if not self.finalize_config():
                return False

            current_step += 1
            self._print_step(current_step, total_steps, "配置证书同步")
            if not self.setup_cert_sync():
                return False

        if tcp_services:
            current_step += 1
            self._print_step(current_step, total_steps, "部署 TCP stream 配置")
            if not self.deploy_stream_config():
                return False

        current_step += 1
        self._print_step(current_step, total_steps, "验证部署")
        self.verify_deployment()
        self.print_summary()

        return True


def main():
    script_dir = Path(__file__).parent.resolve()
    os.chdir(script_dir)

    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"

    deployer = NginxProxyDeployer(config_path)
    success = deployer.deploy()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
