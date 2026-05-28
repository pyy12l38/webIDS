import subprocess
import sys
import os
import shutil
import signal
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_PYTHON = os.path.join(BASE_DIR, ".venv", "bin", "python")
LOCAL_NGINX_CONF = os.path.join(BASE_DIR, "vuln_php_site", "deploy", "nginx-vuln-site.local.conf")
PROXY_BLOG_PORT = 5002
BACKEND_BLOG_PORT = 15002
PROXY_PHP_PORT = 8080
BACKEND_PHP_PORT = 18080
PROXY_HONEYPOT_PORT = 8091
BACKEND_HONEYPOT_PORT = 18091

processes = []
PROJECT_SERVICE_PATTERNS = [
    "ids_site/proxy_gateway.py",
    "ids_site/app.py",
    "target_site/app.py",
    "standalone_honeypot/app.py",
    "router.php",
    "php-fpm --nodaemonize",
]
MANAGED_PORTS = [
    5001,
    PROXY_BLOG_PORT,
    PROXY_PHP_PORT,
    PROXY_HONEYPOT_PORT,
    BACKEND_BLOG_PORT,
    BACKEND_PHP_PORT,
    BACKEND_HONEYPOT_PORT,
    9000,
]


def get_project_python():
    if os.path.exists(PROJECT_PYTHON):
        return PROJECT_PYTHON
    return sys.executable


def run_quiet(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def pids_for_pattern(pattern):
    result = run_quiet(["pgrep", "-f", pattern])
    if result.returncode != 0:
        return []
    pids = []
    current_pid = os.getpid()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            pid = int(line)
        except ValueError:
            continue
        if pid != current_pid:
            pids.append(pid)
    return pids


def terminate_pid(pid, label):
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"[*] 清理旧进程 {label}: pid={pid}")
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        print(f"[!] 无权限终止进程 {label}: pid={pid}")
        return False


def listener_pids(port):
    result = run_quiet(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"])
    if result.returncode != 0:
        return []
    pids = []
    current_pid = os.getpid()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            pid = int(line)
        except ValueError:
            continue
        if pid != current_pid:
            pids.append(pid)
    return pids


def command_for_pid(pid):
    result = run_quiet(["ps", "-p", str(pid), "-o", "command="])
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def stop_local_nginx():
    nginx = shutil.which("nginx")
    if not nginx:
        return
    nginx_pids = listener_pids(BACKEND_PHP_PORT)
    project_nginx_pids = []
    for pid in nginx_pids:
        command = command_for_pid(pid)
        lowered = command.lower()
        if "nginx" in lowered and LOCAL_NGINX_CONF.lower() in lowered:
            project_nginx_pids.append(pid)
    if project_nginx_pids:
        result = run_quiet([nginx, "-c", LOCAL_NGINX_CONF, "-s", "stop"])
        if result.returncode == 0:
            print("[*] 已请求停止项目 Nginx")
        else:
            print("[!] 项目 Nginx 常规停止失败，改用进程终止")
            for pid in project_nginx_pids:
                terminate_pid(pid, "nginx-vuln-site.local.conf")


def stop_local_php_fpm():
    for pid in listener_pids(9000):
        command = command_for_pid(pid).lower()
        if "php-fpm" in command:
            terminate_pid(pid, "php-fpm:9000")


def stop_stale_python_listeners():
    for port in MANAGED_PORTS:
        for pid in listener_pids(port):
            command = command_for_pid(pid)
            lowered = command.lower()
            if "python" not in lowered:
                continue
            is_project_service = any(
                marker in command
                for marker in (
                    "ids_site/app.py",
                    "ids_site/proxy_gateway.py",
                    "target_site/app.py",
                    "standalone_honeypot/app.py",
                )
            )
            is_honeypot_backend = port == BACKEND_HONEYPOT_PORT and command.endswith(" app.py")
            if is_project_service or is_honeypot_backend:
                terminate_pid(pid, f"python-listener:{port}")


def wait_for_ports_release(ports, timeout_seconds=4.0):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        occupied = {port: listener_pids(port) for port in ports}
        occupied = {port: pids for port, pids in occupied.items() if pids}
        if not occupied:
            return True
        time.sleep(0.25)
    return False


def preflight_cleanup():
    print("[*] 启动前清理旧项目服务与端口占用")
    seen = set()
    for pattern in PROJECT_SERVICE_PATTERNS:
        for pid in pids_for_pattern(pattern):
            if pid in seen:
                continue
            seen.add(pid)
            terminate_pid(pid, pattern)
    stop_stale_python_listeners()
    stop_local_nginx()
    stop_local_php_fpm()
    wait_for_ports_release(MANAGED_PORTS)


def print_port_conflicts(ports):
    conflicts = []
    for port in ports:
        pids = listener_pids(port)
        if not pids:
            continue
        for pid in pids:
            conflicts.append((port, pid, command_for_pid(pid)))
    if not conflicts:
        return False
    print("[!] 以下端口仍被占用，新的服务可能无法完整启动：")
    for port, pid, command in conflicts:
        print(f"    - 端口 {port}: pid={pid} {command}")
    return True

def start_process(cmd, name, cwd=None):
    print(f"[+] 启动 {name}")
    p = subprocess.Popen(cmd, cwd=cwd if cwd else BASE_DIR)
    processes.append(p)


def start_process_with_env(cmd, name, env=None, cwd=None):
    print(f"[+] 启动 {name}")
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    p = subprocess.Popen(cmd, cwd=cwd if cwd else BASE_DIR, env=merged_env)
    processes.append(p)


def prefer_local_nginx():
    mode = os.environ.get("IDS_PHP_MODE", "").strip().lower()
    if mode == "builtin":
        return False
    return True

def main():

    print("====== 启动 IDS 实验平台 ======")
    python_cmd = get_project_python()
    print(f"[*] 使用 Python: {python_cmd}")
    preflight_cleanup()
    print_port_conflicts(MANAGED_PORTS)

    # 1 启动 IDS
    start_process(
        [python_cmd, "ids_site/app.py"],
        "IDS平台 (5001)"
    )

    # 2 启动博客后端（内部端口）
    start_process_with_env(
        [python_cmd, "target_site/app.py"],
        f"博客后端 ({BACKEND_BLOG_PORT})",
        env={"TARGET_SITE_PORT": str(BACKEND_BLOG_PORT)}
    )

    # 3 启动轻量代理网关（接管 Proxy 单模式站点）
    start_process(
        [python_cmd, "ids_site/proxy_gateway.py"],
        "代理网关"
    )

    # 4 启动蜜罐后端（内部端口）
    honeypot_dir = os.path.join(BASE_DIR, "standalone_honeypot")
    if os.path.exists(os.path.join(honeypot_dir, "app.py")):
        start_process_with_env(
            [python_cmd, "app.py"],
            f"蜜罐后端 ({BACKEND_HONEYPOT_PORT})",
            env={"HONEYPOT_PORT": str(BACKEND_HONEYPOT_PORT)},
            cwd=honeypot_dir,
        )
    else:
        print("[!] 未找到蜜罐，跳过蜜罐启动")

    # 5 启动 PHP 漏洞站后端（内部端口）
    php = shutil.which("php")
    nginx = shutil.which("nginx")
    php_fpm = shutil.which("php-fpm")

    if prefer_local_nginx() and nginx and php_fpm and os.path.exists(LOCAL_NGINX_CONF):
        start_process(
            [php_fpm, "--nodaemonize"],
            "PHP-FPM (9000)"
        )
        start_process(
            [nginx, "-c", LOCAL_NGINX_CONF, "-g", "daemon off;"],
            f"Nginx-PHP后端 ({BACKEND_PHP_PORT})"
        )

    elif php:

        php_dir = os.path.join(BASE_DIR, "vuln_php_site")

        start_process(
            [
                php,
                "-S",
                f"127.0.0.1:{BACKEND_PHP_PORT}",
                "router.php",
            ],
            f"PHP漏洞后端 ({BACKEND_PHP_PORT})",
            cwd=php_dir
        )

    else:
        print("[!] 未检测到 PHP，跳过 PHP 漏洞站")

    print("\n访问地址：")
    print("IDS平台:  http://127.0.0.1:5001")
    print(f"博客系统: http://127.0.0.1:{PROXY_BLOG_PORT}  (由 IDS 代理网关转发到 {BACKEND_BLOG_PORT})")
    print(f"PHP漏洞:  http://127.0.0.1:{PROXY_PHP_PORT}  (由 IDS 代理网关转发到 {BACKEND_PHP_PORT})")
    print(f"蜜罐:     http://127.0.0.1:{PROXY_HONEYPOT_PORT}  (由 IDS 代理网关转发到 {BACKEND_HONEYPOT_PORT})")

    print("\n按 Ctrl + C 关闭所有服务\n")

    try:
        for p in processes:
            p.wait()

    except KeyboardInterrupt:
        print("\n正在关闭服务...")
        for p in processes:
            p.terminate()

if __name__ == "__main__":
    main()
