#!/usr/bin/env python3
"""
Nginx 反向代理一键部署脚本
用于将 VPS 配置为 IPv6 NAS 的反向代理

支持:
    - HTTP/HTTPS 反向代理 (WebSocket)
    - TCP 流代理 (SSH, 数据库等)

使用方法:
    1. 编辑 config.yaml 配置文件
    2. 运行: python3 deploy.py

依赖:
    - Python 3.6+
    - PyYAML: pip3 install pyyaml
    - sshpass: brew install sshpass (macOS) 或 apt install sshpass (Linux)
"""

import subprocess
import sys
import os
import shutil
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
        self._check_dependencies()

    def _load_config(self) -> dict:
        """加载 YAML 配置文件"""
        if not self.config_path.exists():
            print(f"错误: 配置文件 {self.config_path} 不存在")
            sys.exit(1)

        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def _check_dependencies(self):
        """检查必要的依赖"""
        if not shutil.which("sshpass"):
            print("错误: 未找到 sshpass")
            print("  macOS: brew install sshpass")
            print("  Ubuntu/Debian: apt install sshpass")
            sys.exit(1)

    def _ssh_cmd(self, command: str, timeout: int = 120) -> tuple[int, str, str]:
        """执行远程 SSH 命令"""
        server = self.config['server']
        ssh_command = [
            "sshpass", "-p", server['password'],
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-p", str(server.get('port', 22)),
            f"{server['user']}@{server['host']}",
            command
        ]

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

        # 添加 TCP 服务端口
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
            # UFW 可能未安装，不是致命错误
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

        # Resolver 配置
        resolver_servers = " ".join(resolver['servers'])
        resolver_ipv6 = "ipv6=on" if resolver.get('ipv6', True) else "ipv6=off"

        nginx_config = f'''# ===========================================
# NAS 反向代理配置 (自动生成)
# 后端: {backend['host']}
# ===========================================

# 全局 resolver 配置
resolver {resolver_servers} {resolver_ipv6} valid={resolver.get('valid', '300s')};
resolver_timeout {resolver.get('timeout', '5s')};

'''

        # 为每个服务生成配置
        first_ssl_domain = services[0]['domain'] if services else None

        for i, service in enumerate(services):
            name = service['name']
            domain = service['domain']
            port = service['backend_port']
            websocket = service.get('websocket', False)
            host_header = service.get('host_header', 'frontend')
            timeout = service.get('timeout', {'connect': 60, 'send': 60, 'read': 60})

            # 使用第一个域名的证书路径 (certbot 会合并)
            ssl_domain = first_ssl_domain

            # IPv6 监听配置 (第一个服务使用 ipv6only=on)
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

    # SSL 证书
    ssl_certificate /etc/letsencrypt/live/{ssl_domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{ssl_domain}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # 后端配置 (变量方式实现运行时 DNS 解析)
    set $backend_host "{backend['host']}";
    set $backend_port {port};

    location / {{
        proxy_pass http://$backend_host:$backend_port;

'''

            # Host 头配置
            if host_header == 'backend':
                nginx_config += '        proxy_set_header Host $backend_host:$backend_port;\n'
            else:
                nginx_config += '        proxy_set_header Host $host;\n'

            nginx_config += '''        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_http_version 1.1;
'''

            # WebSocket 支持
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

        stream_config = f'''# ===========================================
# TCP 流代理配置 (自动生成)
# 后端: {backend}
# ===========================================

resolver {resolver_servers} {resolver_ipv6} valid={resolver.get('valid', '300s')};
resolver_timeout {resolver.get('timeout', '5s')};

'''

        for svc in tcp_services:
            name = svc['name']
            listen_port = svc['listen_port']
            backend_port = svc['backend_port']

            stream_config += f'''# {name.upper()} 代理
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

        # 生成配置内容
        nginx_config = self._generate_nginx_config()
        websocket_map = self._generate_websocket_map()

        # 先部署临时 HTTP 配置 (用于 certbot 验证)
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

            # 部署 WebSocket 映射
            cmd = f"cat > /etc/nginx/conf.d/websocket_map.conf << 'EOFWS'\n{websocket_map}EOFWS"
            code, _, stderr = self._ssh_cmd(cmd)
            if code != 0:
                print(f"✗ WebSocket 映射配置失败: {stderr}")
                return False

            # 部署临时配置
            cmd = f"cat > /etc/nginx/conf.d/nas_proxy.conf << 'EOFTEMP'\n{temp_config}EOFTEMP"
            code, _, stderr = self._ssh_cmd(cmd)
            if code != 0:
                print(f"✗ 临时配置部署失败: {stderr}")
                return False

            # 测试并重载
            code, _, stderr = self._ssh_cmd("nginx -t && systemctl reload nginx")
            if code != 0:
                print(f"✗ Nginx 配置测试失败: {stderr}")
                return False

            print("✓ HTTP 临时配置部署完成")

        # 保存完整配置供后续使用
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

        # 创建 stream 配置目录
        code, _, _ = self._ssh_cmd("mkdir -p /etc/nginx/stream.conf.d")
        if code != 0:
            print("✗ 创建 stream 配置目录失败")
            return False

        # 部署 stream 配置文件
        cmd = f"cat > /etc/nginx/stream.conf.d/tcp_proxy.conf << 'EOFSTREAM'\n{stream_config}EOFSTREAM"
        code, _, stderr = self._ssh_cmd(cmd)
        if code != 0:
            print(f"✗ Stream 配置部署失败: {stderr}")
            return False

        # 检查 nginx.conf 是否已包含 stream 块
        code, stdout, _ = self._ssh_cmd("grep -c 'stream.conf.d' /etc/nginx/nginx.conf || echo '0'")
        if '0' in stdout:
            # 添加 stream include 到 nginx.conf
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

        # 测试配置
        code, _, stderr = self._ssh_cmd("nginx -t")
        if code != 0:
            print(f"✗ Nginx 配置测试失败: {stderr}")
            return False

        # 重载 Nginx
        code, _, stderr = self._ssh_cmd("systemctl reload nginx")
        if code != 0:
            print(f"✗ Nginx 重载失败: {stderr}")
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

        # 部署完整配置
        cmd = f"cat > /etc/nginx/conf.d/nas_proxy.conf << 'EOFFINAL'\n{self._full_nginx_config}EOFFINAL"
        code, _, stderr = self._ssh_cmd(cmd)
        if code != 0:
            print(f"✗ 配置部署失败: {stderr}")
            return False

        # 测试并重载
        code, stdout, stderr = self._ssh_cmd("nginx -t && systemctl reload nginx")
        if code != 0:
            print(f"✗ Nginx 配置测试失败: {stderr}")
            return False

        print("✓ HTTP 配置部署完成")
        return True

    def verify_deployment(self) -> bool:
        """验证部署"""
        print("验证部署...")

        # 检查 Nginx 状态
        code, stdout, _ = self._ssh_cmd("systemctl is-active nginx")
        if code == 0 and "active" in stdout:
            print("✓ Nginx 运行正常")
        else:
            print("✗ Nginx 未运行")
            return False

        # 检查证书
        services = self.config.get('services', [])
        if services:
            code, stdout, _ = self._ssh_cmd("certbot certificates 2>/dev/null | grep -E 'Domains:|Expiry'")
            if code == 0:
                print("✓ SSL 证书状态:")
                for line in stdout.strip().split('\n'):
                    print(f"    {line.strip()}")

            # 测试 HTTP 后端连通性
            backend = self.config['backend']['host']
            port = services[0]['backend_port']
            code, _, _ = self._ssh_cmd(f"curl -s --connect-timeout 5 -o /dev/null -w '%{{http_code}}' http://{backend}:{port}/")
            if code == 0:
                print(f"✓ HTTP 后端 {backend} 连接正常")
            else:
                print(f"⚠ HTTP 后端连接测试失败 (可能是正常的)")

        # 验证 TCP 端口监听
        tcp_services = self.config.get('tcp_services', [])
        if tcp_services:
            code, stdout, _ = self._ssh_cmd("ss -tlnp | grep nginx")
            for svc in tcp_services:
                port = svc['listen_port']
                if f":{port}" in stdout:
                    print(f"✓ TCP 端口 {port} ({svc['name']}) 监听正常")
                else:
                    print(f"✗ TCP 端口 {port} ({svc['name']}) 未监听")

            # 测试 TCP 后端连通性
            backend = self.config['backend']['host']
            for svc in tcp_services:
                backend_port = svc['backend_port']
                code, _, _ = self._ssh_cmd(
                    f"timeout 5 bash -c '</dev/tcp/{backend}/{backend_port}' 2>/dev/null && echo 'ok' || echo 'fail'"
                )
                # 使用 nc 测试
                code, stdout, _ = self._ssh_cmd(
                    f"nc -z -w 5 {backend} {backend_port} && echo 'ok' || echo 'fail'"
                )
                if 'ok' in stdout:
                    print(f"✓ TCP 后端 {backend}:{backend_port} ({svc['name']}) 连接正常")
                else:
                    print(f"⚠ TCP 后端 {backend}:{backend_port} ({svc['name']}) 连接测试失败")

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
                # 获取对应的域名 (如果有的话，使用第一个 HTTP 服务的域名)
                if services:
                    domain = services[0]['domain'].split('.', 1)[1]  # 获取主域名
                    print(f"  - {svc['name']}: {server_host}:{svc['listen_port']}")
                    print(f"    示例: ssh -p {svc['listen_port']} user@{server_host}")
                else:
                    print(f"  - {svc['name']}: {server_host}:{svc['listen_port']}")

        print("\n配置文件位置 (远程服务器):")
        print("  - /etc/nginx/conf.d/nas_proxy.conf")
        print("  - /etc/nginx/conf.d/websocket_map.conf")
        if tcp_services:
            print("  - /etc/nginx/stream.conf.d/tcp_proxy.conf")
        if services:
            print("  - /etc/letsencrypt/live/*/")

        print("\n常用维护命令:")
        print("  nginx -t              # 测试配置")
        print("  systemctl reload nginx # 重载配置")
        print("  certbot renew         # 续期证书")
        print("  tail -f /var/log/nginx/error.log  # 查看错误日志")

    def deploy(self):
        """执行完整部署"""
        services = self.config.get('services', [])
        tcp_services = self.config.get('tcp_services', [])

        # 计算总步骤数
        total_steps = 4  # 基本步骤: 连接、安装、防火墙、验证
        if services:
            total_steps += 3  # HTTP: 部署临时配置、申请证书、部署最终配置
        if tcp_services:
            total_steps += 1  # TCP: 部署 stream 配置

        print("\n" + "=" * 50)
        print("Nginx 反向代理一键部署")
        print("=" * 50)
        print(f"目标服务器: {self.config['server']['host']}")
        print(f"后端地址: {self.config['backend']['host']}")
        print(f"HTTP 服务数量: {len(services)}")
        print(f"TCP 服务数量: {len(tcp_services)}")

        current_step = 0

        # Step: 测试连接
        current_step += 1
        self._print_step(current_step, total_steps, "测试 SSH 连接")
        if not self.test_connection():
            return False

        # Step: 安装软件包
        current_step += 1
        self._print_step(current_step, total_steps, "安装 Nginx 和 Certbot")
        if not self.install_packages():
            return False

        # Step: 配置防火墙
        current_step += 1
        self._print_step(current_step, total_steps, "配置防火墙")
        if not self.configure_firewall():
            return False

        # HTTP 服务配置
        if services:
            # Step: 部署 Nginx 临时配置
            current_step += 1
            self._print_step(current_step, total_steps, "部署 Nginx HTTP 配置")
            if not self.deploy_nginx_config():
                return False

            # Step: 申请 SSL 证书
            current_step += 1
            self._print_step(current_step, total_steps, "申请 SSL 证书")
            if not self.request_certificates():
                return False

            # Step: 部署最终配置
            current_step += 1
            self._print_step(current_step, total_steps, "部署最终 HTTP 配置")
            if not self.finalize_config():
                return False

        # TCP 服务配置
        if tcp_services:
            current_step += 1
            self._print_step(current_step, total_steps, "部署 TCP stream 配置")
            if not self.deploy_stream_config():
                return False

        # Step: 验证
        current_step += 1
        self._print_step(current_step, total_steps, "验证部署")
        self.verify_deployment()
        self.print_summary()

        return True


def main():
    # 切换到脚本所在目录
    script_dir = Path(__file__).parent.resolve()
    os.chdir(script_dir)

    # 支持自定义配置文件路径
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"

    deployer = NginxProxyDeployer(config_path)
    success = deployer.deploy()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
