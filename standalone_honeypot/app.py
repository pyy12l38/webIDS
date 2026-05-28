from __future__ import annotations

import datetime
import json
import os
import re
import time
from threading import Lock
from urllib.parse import unquote_plus, urlencode

from flask import Flask, Response, abort, jsonify, render_template, request
from werkzeug.utils import secure_filename


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
LOG_DIR = os.path.join(BASE_DIR, "logs")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ACCESS_LOG = os.path.join(LOG_DIR, "access.log")
CAPTURE_LOG = os.path.join(LOG_DIR, "captures.jsonl")
CONSOLE_TOKEN = os.environ.get("HONEYPOT_CONSOLE_TOKEN", "lab")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.secret_key = os.environ.get("HONEYPOT_SECRET_KEY", "honeypot-dev-secret")
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

CAPTURE_LOCK = Lock()
UPLOAD_LOCK = Lock()

FAKE_ENV = """APP_ENV=production
APP_DEBUG=false
APP_NAME=GatewayEdge
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=tenant_core
DB_USERNAME=ops_service
DB_PASSWORD=Sup3rWeakPass!
REDIS_URL=redis://127.0.0.1:6379/0
JWT_SECRET=demo-gateway-secret
"""

FAKE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = git@gitlab.internal:infra/gateway-edge.git
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/false
deploy:x:1001:1001:Deploy Service:/home/deploy:/bin/bash
"""

FAKE_METADATA = {
    "instance-id": "i-demo8f3c2aa9",
    "hostname": "edge-gateway-prod-01",
    "ami-id": "ami-0d3cafe1234567890",
    "security-groups": ["sg-edge-web", "sg-edge-admin"],
}

SUSPICIOUS_PATH_HINTS = (
    "phpmyadmin",
    "wp-login",
    ".env",
    ".git",
    "actuator",
    "jenkins",
    "manager",
    "shell",
    "admin",
    "login",
    "backup",
    "swagger",
    "cgi-bin",
    "vendor",
)


def now_text() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_client_ip() -> str:
    forwarded = (request.headers.get("X-Forwarded-For") or "").strip()
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.remote_addr or "-"


def short_text(value: object, limit: int = 500) -> str:
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "...[truncated]"


def build_logged_query() -> str:
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def push(key: str, value: object) -> None:
        text = short_text(value, 800).strip()
        if not key or not text:
            return
        item = (key, text)
        if item in seen:
            return
        seen.add(item)
        pairs.append(item)

    for key in request.args:
        for value in request.args.getlist(key):
            push(key, value)

    for key in request.form:
        for value in request.form.getlist(key):
            push(key, value)

    for key in request.files:
        for storage in request.files.getlist(key):
            if storage and storage.filename:
                push(f"{key}_filename", storage.filename)

    if request.is_json:
        payload = request.get_json(silent=True)
        if payload is not None:
            push("json", json.dumps(payload, ensure_ascii=False, sort_keys=True))

    content_type = (request.content_type or "").lower()
    raw_body = request.get_data(cache=True, as_text=True)
    if raw_body and "multipart/form-data" not in content_type and not request.form and not request.is_json:
        push("body", raw_body)

    if request.content_type:
        push("content_type", request.content_type)

    return unquote_plus(urlencode(pairs, doseq=True))[:4000]


def record_capture(category: str, summary: str, details: dict | None = None, severity: str = "medium") -> None:
    request.environ["honeypot.capture"] = True
    payload = {
        "time": now_text(),
        "category": category,
        "severity": severity,
        "summary": summary,
        "details": details or {},
        "ip": get_client_ip(),
        "method": request.method,
        "path": request.path,
        "query": build_logged_query(),
        "user_agent": request.headers.get("User-Agent", ""),
    }
    with CAPTURE_LOCK:
        with open(CAPTURE_LOG, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def load_recent_captures(limit: int = 120) -> list[dict]:
    items: list[dict] = []
    if not os.path.exists(CAPTURE_LOG):
        return items
    with open(CAPTURE_LOG, "r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(reversed(items[-limit:]))


def console_authorized() -> bool:
    query_token = (request.args.get("token") or "").strip()
    header_token = (request.headers.get("X-Honeypot-Token") or "").strip()
    return bool(CONSOLE_TOKEN) and (query_token == CONSOLE_TOKEN or header_token == CONSOLE_TOKEN)


def fake_shell_output(command: str) -> str:
    normalized = (command or "").strip().lower()
    if not normalized:
        return ""
    if normalized == "whoami":
        return "www-data"
    if normalized == "id":
        return "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
    if normalized.startswith("uname"):
        return "Linux edge-gateway-prod-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
    if "cat /etc/passwd" in normalized:
        return FAKE_PASSWD
    if "pwd" == normalized:
        return "/var/www/gateway"
    if "ls" == normalized or normalized.startswith("ls "):
        return "app\nbootstrap\nconfig\npublic\nstorage\nvendor"
    if "curl" in normalized or "wget" in normalized:
        return "curl: (7) Failed to connect to upstream host"
    if "python" in normalized or "bash" in normalized or "sh " in normalized:
        return "permission denied"
    return f"/bin/sh: {command}: command not found"


def fake_proxy_response(target: str) -> tuple[str, str]:
    target_lower = (target or "").lower()
    if "169.254.169.254" in target_lower:
        return (
            json.dumps(FAKE_METADATA, ensure_ascii=False, indent=2),
            "application/json; charset=utf-8",
        )
    if "localhost" in target_lower or "127.0.0.1" in target_lower:
        return "upstream localhost:8080 returned 500", "text/plain; charset=utf-8"
    if target_lower.startswith("file://"):
        return "open_basedir restriction in effect", "text/plain; charset=utf-8"
    return "upstream timeout after 2000ms", "text/plain; charset=utf-8"


def service_cards() -> list[dict]:
    return [
        {
            "title": "管理后台",
            "desc": "伪装成运维后台，常见爆破入口。",
            "href": "/admin/login",
        },
        {
            "title": "phpMyAdmin",
            "desc": "吸引数据库口令尝试与扫描器探测。",
            "href": "/phpmyadmin",
        },
        {
            "title": "Web Shell",
            "desc": "接收命令执行探测参数和恶意命令。",
            "href": "/shell",
        },
        {
            "title": "固件上传",
            "desc": "模拟可疑文件投递与木马上传入口。",
            "href": "/upload",
        },
        {
            "title": "调试代理",
            "desc": "接收 SSRF 风格的外连目标。",
            "href": "/api/proxy",
        },
        {
            "title": "敏感文件",
            "desc": "诱导访问 /.env、/.git/config、/backup.zip。",
            "href": "/.env",
        },
    ]


@app.before_request
def tag_suspicious_scans() -> None:
    path = request.path.lower()
    if request.method == "GET" and any(token in path for token in SUSPICIOUS_PATH_HINTS):
        if path not in {
            "/admin/login",
            "/phpmyadmin",
            "/wp-login.php",
            "/shell",
            "/upload",
            "/api/proxy",
            "/.env",
            "/.git/config",
            "/backup.zip",
            "/server-status",
            "/actuator/health",
        }:
            record_capture(
                category="scan",
                summary=f"命中敏感探测路径 {request.path}",
                details={"path": request.path},
                severity="low",
            )


@app.after_request
def write_access_log(response: Response) -> Response:
    try:
        line = (
            f"{now_text()}\t{get_client_ip()}\t{request.method}\t{request.path}\t"
            f"{build_logged_query()}\t{response.status_code}\t-\t{request.headers.get('User-Agent', '')}\n"
        )
        with open(ACCESS_LOG, "a", encoding="utf-8") as handle:
            handle.write(line)
    except Exception as exc:
        print("write access log failed:", exc)
    return response


@app.route("/")
def index():
    return render_template("index.html", cards=service_cards(), console_token=CONSOLE_TOKEN)


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True, "service": "standalone_honeypot", "time": now_text()})


@app.route("/robots.txt")
def robots():
    body = "User-agent: *\nDisallow: /admin/\nDisallow: /backup.zip\nDisallow: /.env\n"
    return Response(body, mimetype="text/plain")


@app.route("/admin/login", methods=["GET", "POST"])
@app.route("/wp-login.php", methods=["GET", "POST"])
@app.route("/phpmyadmin", methods=["GET", "POST"])
def login_traps():
    product_name = {
        "/admin/login": "Gateway Admin",
        "/wp-login.php": "WordPress",
        "/phpmyadmin": "phpMyAdmin",
    }.get(request.path, "Admin")
    message = ""
    status = 200
    if request.method == "POST":
        username = request.form.get("username") or request.form.get("log") or request.form.get("email") or ""
        password = request.form.get("password") or request.form.get("pwd") or request.form.get("pass") or ""
        record_capture(
            category="credential",
            summary=f"{product_name} 登录尝试",
            details={"username": username, "password": password},
            severity="high",
        )
        time.sleep(0.35)
        message = "Authentication failed. Invalid username or password."
        status = 401
    return (
        render_template(
            "login.html",
            product_name=product_name,
            message=message,
            request_path=request.path,
        ),
        status,
    )


@app.route("/shell", methods=["GET", "POST"])
def shell():
    command = request.values.get("cmd", "")
    output = ""
    if command:
        record_capture(
            category="command",
            summary="命令执行探测",
            details={"cmd": command},
            severity="high",
        )
        output = fake_shell_output(command)
    return render_template("shell.html", command=command, output=output)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    message = ""
    saved_name = ""
    if request.method == "POST":
        storage = request.files.get("file")
        if storage and storage.filename:
            original_name = storage.filename
            safe_name = secure_filename(original_name) or "sample.bin"
            final_name = f"{int(time.time())}_{safe_name}"
            target_path = os.path.join(UPLOAD_DIR, final_name)
            with UPLOAD_LOCK:
                storage.save(target_path)
            record_capture(
                category="upload",
                summary="文件上传尝试",
                details={"filename": original_name, "saved_as": final_name},
                severity="high",
            )
            message = "Firmware package queued for asynchronous scanning."
            saved_name = final_name
        else:
            message = "No package selected."
    return render_template("upload.html", message=message, saved_name=saved_name)


@app.route("/api/proxy", methods=["GET", "POST"])
def proxy():
    target = request.values.get("url", "")
    response_text = ""
    response_type = "text/plain; charset=utf-8"
    if target:
        record_capture(
            category="ssrf",
            summary="代理拉取目标被请求",
            details={"url": target},
            severity="high",
        )
        response_text, response_type = fake_proxy_response(target)

    wants_raw = request.args.get("raw") == "1"
    if wants_raw and target:
        return Response(response_text, mimetype=response_type)
    return render_template("proxy.html", target=target, response_text=response_text)


@app.route("/.env")
def dot_env():
    record_capture(
        category="secret_probe",
        summary="访问敏感文件 /.env",
        details={"path": "/.env"},
        severity="medium",
    )
    return Response(FAKE_ENV, mimetype="text/plain")


@app.route("/.git/config")
def git_config():
    record_capture(
        category="secret_probe",
        summary="访问敏感文件 /.git/config",
        details={"path": "/.git/config"},
        severity="medium",
    )
    return Response(FAKE_GIT_CONFIG, mimetype="text/plain")


@app.route("/backup.zip")
def backup_zip():
    record_capture(
        category="secret_probe",
        summary="尝试下载备份包",
        details={"path": "/backup.zip"},
        severity="medium",
    )
    payload = b"PK\x03\x04demo-backup-not-real"
    return Response(
        payload,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=backup.zip"},
    )


@app.route("/server-status")
def server_status():
    record_capture(
        category="probe",
        summary="探测 server-status",
        details={"path": "/server-status"},
        severity="low",
    )
    body = "BusyWorkers: 2\nIdleWorkers: 8\nReqPerSec: 0.31\n"
    return Response(body, mimetype="text/plain")


@app.route("/actuator/health")
def actuator_health():
    record_capture(
        category="probe",
        summary="探测 actuator 健康检查",
        details={"path": "/actuator/health"},
        severity="low",
    )
    return jsonify({"status": "UP", "components": {"db": {"status": "UP"}, "redis": {"status": "UP"}}})


@app.route("/__console__")
def console():
    if not console_authorized():
        abort(404)
    captures = load_recent_captures()
    for item in captures:
        item["details_text"] = json.dumps(item.get("details") or {}, ensure_ascii=False, indent=2)
    return render_template("console.html", captures=captures)


@app.errorhandler(404)
def not_found(_error):
    path = request.path.lower()
    if any(token in path for token in SUSPICIOUS_PATH_HINTS):
        record_capture(
            category="scan",
            summary=f"404 敏感路径探测 {request.path}",
            details={"path": request.path},
            severity="low",
        )
    return render_template("not_found.html", path=request.path), 404


if __name__ == "__main__":
    port = int(os.environ.get("HONEYPOT_PORT", "8091"))
    debug_mode = os.environ.get("HONEYPOT_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app.run(host="0.0.0.0", port=port, debug=debug_mode, use_reloader=False)
