import base64
import datetime
import importlib.util
import json
import os
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, unquote_plus
from urllib.request import Request, urlopen

from flask import (
    Flask,
    Response,
    abort,
    redirect,
    render_template,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_PYTHON = os.path.abspath(os.path.join(BASE_DIR, "..", ".venv", "bin", "python"))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

if os.path.exists(PROJECT_PYTHON) and os.path.realpath(sys.executable) != os.path.realpath(PROJECT_PYTHON):
    os.execv(PROJECT_PYTHON, [PROJECT_PYTHON, __file__, *sys.argv[1:]])

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

IDS_SITE_DIR = os.path.join(PROJECT_ROOT, "ids_site")
if IDS_SITE_DIR not in sys.path:
    sys.path.insert(0, IDS_SITE_DIR)


def _load_local_module(module_name, module_path):
    if not os.path.exists(module_path):
        return None
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    from ids_site.blocklist import is_ip_blocked
except ModuleNotFoundError:
    try:
        from blocklist import is_ip_blocked
    except ModuleNotFoundError:
        blocklist = _load_local_module("blocklist_local", os.path.join(IDS_SITE_DIR, "blocklist.py"))
        if blocklist is not None:
            is_ip_blocked = blocklist.is_ip_blocked
        else:
            def is_ip_blocked(ip):
                return False


app = Flask(__name__)

LOG_DIR = os.path.join(BASE_DIR, "logs")
ACCESS_LOG = os.path.abspath(os.path.join(LOG_DIR, "access.log"))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
VULN_UPLOAD_FOLDER = os.path.join(BASE_DIR, "vuln_uploads")

print("[*] ACCESS_LOG =", ACCESS_LOG)

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(VULN_UPLOAD_FOLDER, exist_ok=True)

app.secret_key = os.environ.get("TARGET_SITE_SECRET_KEY", "dev-secret-key-for-demo")

ALLOWED_EXTENSIONS = {"txt", "md", "pdf", "png", "jpg", "jpeg"}
SCRIPT_LIKE_EXTENSIONS = {"php", "phtml", "jsp", "jspx", "asp", "aspx", "cgi", "pl"}

DEMO_USER = {
    "username": "admin",
    "password": "admin123",
}

ARTICLES = {
    1: {
        "title": "从 0 到 1：用 Flask 搭建一个可被 IDS 监测的博客网站",
        "time": "2026-03-03",
        "content": (
            "这篇文章记录我如何从零开始搭建一个简单的 Flask 博客系统。\n\n"
            "目标：\n"
            "1）提供首页文章列表与文章详情页\n"
            "2）提供管理员登录后台\n"
            "3）提供文章上传能力（仅登录后可用）\n\n"
            "为什么要做这个网站？\n"
            "因为我的毕业设计是《基于网络流量分析的入侵检测系统设计与实现》。\n"
            "这个博客站点将作为“被检测网站”，产生真实访问流量，并把日志上报给 IDS 平台。\n\n"
            "下一步：\n"
            "把访问日志上报 + IDS 检测规则/机器学习接入，形成完整闭环。"
        ),
    },
    2: {
        "title": "Web 攻击快速入门：SQL 注入与 XSS 在 HTTP 流量中的典型特征",
        "time": "2026-03-03",
        "content": (
            "在 IDS / WAF 设计中，理解攻击在 HTTP 流量里长什么样非常重要。\n\n"
            "SQL 注入常见特征：\n"
            "- 参数中出现 or 1=1、union select、select ... from\n"
            "- 引号闭合后拼接条件\n"
            "- 注释符号 --、#、/* */\n\n"
            "XSS 常见特征：\n"
            "- <script>、javascript:\n"
            "- 事件触发 onerror=、onload=\n"
            "- HTML 标签注入 <img ...> <svg ...>\n\n"
            "在工程实现里，规则检测要做：\n"
            "1）URL 多层解码\n"
            "2）大小写规整\n"
            "3）常见绕过字符处理\n\n"
            "在机器学习里，重点是特征工程：长度、特殊字符比例、编码次数、访问频率、路径敏感性等。"
        ),
    },
    3: {
        "title": "Python 博客功能实验区上线：把真实功能点接入 IDS 检测链路",
        "time": "2026-03-22",
        "content": (
            "为了让 IDS 不只依赖单一的漏洞演示页，博客系统新增了一组 Python 版功能实验入口。\n\n"
            "这些入口仍然属于博客系统的一部分，只是刻意保留了较弱的输入处理，便于生成可被 IDS 识别的攻击样本。\n\n"
            "当前可覆盖：\n"
            "- 搜索调试（SQL 注入）\n"
            "- 评论预览与评论区（XSS）\n"
            "- 后台诊断页（RCE）\n"
            "- 媒体上传中心（上传 / WebShell）\n"
            "- 文件预览 / 导入（路径穿越、敏感文件读取）\n"
            "- 远程内容预览、XML 导入、模板预览、成员筛选、跳转设置等后台功能\n\n"
            "实验入口统一通过 /playground 暴露，用于生成更贴近 Python 博客系统语义的 Web 日志样本。"
        ),
    },
}

ARTICLE_COMMENTS = {
    1: [
        {
            "author": "ops-bot",
            "body": "欢迎来到评论区，这里当前为了实验演示不会对评论正文做 HTML 转义。",
            "time": "2026-03-22 22:50:00",
        }
    ],
    2: [],
    3: [],
}

ENV_CONTENT = (
    "APP_ENV=development\n"
    "APP_DEBUG=true\n"
    "DB_HOST=127.0.0.1\n"
    "DB_USER=demo_user\n"
    "DB_PASSWORD=demo-password\n"
    "REDIS_URL=redis://127.0.0.1:6379/0\n"
)

GIT_CONFIG_CONTENT = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "\tfilemode = true\n"
    "\tbare = false\n"
    "\tlogallrefupdates = true\n"
    "[remote \"origin\"]\n"
    "\turl = git@example.com:webids/demo-target.git\n"
)

BACKUP_SQL_CONTENT = (
    "-- demo backup generated for IDS testing\n"
    "CREATE TABLE users (id INT, username VARCHAR(64), password VARCHAR(64));\n"
    "INSERT INTO users VALUES (1, 'admin', 'admin123');\n"
)

SENSITIVE_PROBE_ENDPOINTS = [
    "/.env",
    "/.git/config",
    "/phpmyadmin",
    "/wp-login.php",
    "/swagger",
    "/api-docs",
    "/actuator",
    "/vendor/phpunit/eval-stdin.php",
    "/manager/html",
]

XXE_ENTITY_PATTERN = re.compile(
    r'<!ENTITY\s+([A-Za-z0-9_:-]+)\s+(?:SYSTEM\s+"([^"]+)"|PUBLIC\s+"[^"]*"\s+"([^"]+)")\s*>',
    re.IGNORECASE,
)
PHP_FILTER_PATTERN = re.compile(
    r"^php://filter/convert\.base64-encode/resource=(.+)$",
    re.IGNORECASE,
)
DATA_URI_PATTERN = re.compile(
    r"^data:(?:[^;,]+)?(?:;charset=[^;,]+)?(;base64)?,(.*)$",
    re.IGNORECASE | re.DOTALL,
)


def get_next_article_id():
    return max(ARTICLES.keys(), default=0) + 1


def is_logged_in():
    return session.get("login_user") is not None


def allowed_file(filename):
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def current_base_url():
    return request.host_url.rstrip("/")


def query_link(path, params=None):
    if not params:
        return path
    return f"{path}?{urlencode(params, doseq=True)}"


def redirect_to_canonical(path):
    params = request.args.to_dict(flat=False)
    target = query_link(path, params)
    code = 307 if request.method not in {"GET", "HEAD", "OPTIONS"} else 302
    return redirect(target, code=code)


def demo_site_path(relative=""):
    relative = relative.lstrip("/")
    candidate = os.path.join(BASE_DIR, relative) if relative else BASE_DIR
    return os.path.abspath(candidate)


def demo_file_uri(relative):
    return "file://" + demo_site_path(relative)


def short_text(value, limit=2400):
    if value is None:
        return ""
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]"


def looks_script_like(filename):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in SCRIPT_LIKE_EXTENSIONS


def safe_vuln_filename(filename):
    return os.path.basename((filename or "").strip()) or "upload.bin"


def read_path_like(target):
    match = PHP_FILTER_PATTERN.match(target)
    if match:
        resource = demo_site_path(match.group(1))
        with open(resource, "rb") as handle:
            return base64.b64encode(handle.read()).decode("ascii")

    if target.startswith("file://"):
        file_path = target[len("file://"):]
        with open(file_path, "rb") as handle:
            return handle.read().decode("utf-8", errors="ignore")

    data_match = DATA_URI_PATTERN.match(target)
    if data_match:
        is_base64 = bool(data_match.group(1))
        payload = data_match.group(2)
        if is_base64:
            return base64.b64decode(payload).decode("utf-8", errors="ignore")
        return payload

    if os.path.isabs(target):
        with open(target, "rb") as handle:
            return handle.read().decode("utf-8", errors="ignore")

    local_target = demo_site_path(target)
    with open(local_target, "rb") as handle:
        return handle.read().decode("utf-8", errors="ignore")


def fetch_remote_resource(target):
    if target.startswith("file://") or target.startswith("data:") or target.startswith("php://"):
        return read_path_like(target)

    req = Request(target, headers={"User-Agent": "FlaskVulnLab/1.0"})
    with urlopen(req, timeout=2) as response:
        return response.read(2400).decode("utf-8", errors="ignore")


def simulate_xxe(xml_payload):
    entity_map = {}
    for name, system_target, public_target in XXE_ENTITY_PATTERN.findall(xml_payload):
        source = system_target or public_target
        try:
            entity_map[name] = short_text(fetch_remote_resource(source), 1600)
        except Exception as exc:
            entity_map[name] = f"[entity-load-error] {exc}"

    rendered = xml_payload
    for name, value in entity_map.items():
        rendered = rendered.replace(f"&{name};", value)
    return rendered


def render_ssti(template_text):
    normalized = re.sub(r"\$\{\s*(.*?)\s*\}", r"{{ \1 }}", template_text)
    try:
        return render_template_string(
            normalized,
            user="visitor",
            profile={"role": "guest"},
            config={"items": lambda: ["debug", "lab", "demo"]},
        )
    except Exception as exc:
        return f"[template-error] {exc}"


def _logged_pairs_from_mapping(values):
    if not values:
        return []
    pairs = []
    for key in values:
        for value in values.getlist(key):
            pairs.append((key, value))
    return pairs


def build_logged_query():
    pairs = []
    seen = set()

    def push(key, value):
        text = "" if value is None else str(value)
        text = text.strip()
        if text == "":
            return
        if len(text) > 600:
            text = text[:600]
        item = (key, text)
        if item in seen:
            return
        seen.add(item)
        pairs.append(item)

    for key, value in _logged_pairs_from_mapping(request.args):
        push(key, value)

    for key, value in _logged_pairs_from_mapping(request.form):
        push(key, value)

    for key in request.files:
        for storage in request.files.getlist(key):
            if storage and storage.filename:
                push(f"{key}_filename", storage.filename)

    if request.is_json:
        payload = request.get_json(silent=True)
        if payload is not None:
            push("json", json.dumps(payload, ensure_ascii=False, sort_keys=True))

    if request.content_type:
        push("content_type", request.content_type)

    if request.headers.get("X-HTTP-Method-Override"):
        push("method_override", request.headers.get("X-HTTP-Method-Override"))

    return unquote_plus(urlencode(pairs, doseq=True))[:4000]


def make_example_pairs(examples):
    return list(examples.items())


def vuln_cards():
    admin_url = current_base_url() + "/admin/exposed"
    return [
        {
            "title": "SQL 注入",
            "desc": "通过博客搜索调试功能模拟联合查询、布尔注入、时间盲注和数据库危险函数。",
            "links": make_example_pairs({
                "打开搜索调试": "/search",
                "联合查询": "/search?q=1+UNION+SELECT+null%2Cuser%28%29%2Cdatabase%28%29+--",
                "时间盲注": "/search?q=1%27%3Bwaitfor+delay+%270%3A0%3A5%27--",
            }),
        },
        {
            "title": "XSS",
            "desc": "通过评论预览与评论区输入模拟 script、事件属性、javascript 协议与 SVG 变体。",
            "links": make_example_pairs({
                "打开评论预览": "/comments/preview",
                "script 注入": "/comments/preview?content=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
                "事件型 XSS": "/comments/preview?content=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E",
            }),
        },
        {
            "title": "命令执行 / RCE",
            "desc": "通过后台诊断页模拟 cmd 参数、危险命令词和下载执行特征。",
            "links": make_example_pairs({
                "打开后台诊断": "/admin/debug/exec",
                "执行 whoami": "/admin/debug/exec?cmd=whoami",
                "下载执行特征": "/admin/debug/exec?cmd=curl+http://example.com",
            }),
        },
        {
            "title": "文件上传 / WebShell",
            "desc": "通过后台媒体上传功能模拟双扩展、脚本扩展名和上传后访问。",
            "links": make_example_pairs({
                "打开媒体上传": "/admin/media/upload",
                "访问上传目录": "/uploads/",
            }),
        },
        {
            "title": "路径穿越 / 敏感文件读取",
            "desc": "通过后台文件预览功能模拟 ../、php://filter、file://、data:// 等读取方式。",
            "links": make_example_pairs({
                "打开文件预览": "/admin/files/view",
                "读取 /etc/passwd": "/admin/files/view?file=../../../../etc/passwd",
                "读取 .env": "/.env",
            }),
        },
        {
            "title": "SSRF",
            "desc": "通过远程内容预览功能模拟本机、元数据地址、dict/file 协议访问。",
            "links": make_example_pairs({
                "打开远程预览": "/admin/fetch-preview",
                "访问管理页": query_link("/admin/fetch-preview", {"url": admin_url}),
                "dict 协议": "/admin/fetch-preview?url=dict://127.0.0.1:6379/dbsize",
            }),
        },
        {
            "title": "XXE",
            "desc": "通过 XML 导入功能模拟危险 DTD 和外部实体读取。",
            "links": make_example_pairs({
                "打开 XML 导入": "/admin/xml-import",
                "读取 /etc/passwd": "/admin/xml-import?xml=%3C!DOCTYPE%20foo%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file:///etc/passwd%22%3E%5D%3E%3Cfoo%3E%26xxe%3B%3C/foo%3E",
            }),
        },
        {
            "title": "SSTI / 模板注入",
            "desc": "通过后台模板预览功能模拟 Jinja 风格与 EL 风格表达式执行。",
            "links": make_example_pairs({
                "打开模板预览": "/admin/template-preview",
                "Jinja 风格": "/admin/template-preview?template=%7B%7B7*7%7D%7D",
                "EL 风格": "/admin/template-preview?template=%24%7B7*7%7D",
            }),
        },
        {
            "title": "NoSQL 注入",
            "desc": "通过后台用户筛选功能模拟 $where、$ne、$regex 等 Mongo 风格操作符。",
            "links": make_example_pairs({
                "打开用户筛选": "/admin/member-filter",
                "$where 注入": "/admin/member-filter?filter=%7B%22%24where%22%3A%22this.password.length%3E0%22%7D",
                "$ne 绕过": "/admin/member-filter?username=%7B%22%24ne%22%3Anull%7D&password=%7B%22%24ne%22%3Anull%7D",
            }),
        },
        {
            "title": "开放重定向 / 认证测试",
            "desc": "通过登录与跳转功能模拟 next 重定向、弱认证和后台暴露页面。",
            "links": make_example_pairs({
                "打开跳转页": "/go",
                "外链跳转": "/go?next=http://example.com",
                "打开认证页": "/auth/demo-login",
                "后台入口": "/admin",
            }),
        },
        {
            "title": "参数篡改 / 业务参数攻击",
            "desc": "通过订单确认与权限字段模拟 price、amount、uid、role、is_admin 等关键参数篡改。",
            "links": make_example_pairs({
                "打开订单确认": "/admin/order-review",
                "价格篡改": "/admin/order-review?uid=1001&price=0.01&amount=0.01&quantity=99",
                "权限提权": "/admin/order-review?uid=1001&role=admin&is_admin=1&status=vip",
            }),
        },
        {
            "title": "扫描探测 / 敏感路径",
            "desc": "补齐常见管理入口、框架探测路径与目录爆破目标。",
            "links": make_example_pairs({
                "访问 /phpmyadmin": "/phpmyadmin",
                "访问 /wp-login.php": "/wp-login.php",
                "访问 /swagger": "/swagger",
                "访问 /api-docs": "/api-docs",
            }),
        },
        {
            "title": "批量探测 / 攻击链演练",
            "desc": "一键连续触发敏感路径探测、扫描方法、暴力破解与组合攻击链，更贴近当前 IDS 的行为聚合规则。",
            "links": make_example_pairs({
                "打开批量流量生成器": "/admin/traffic-runner",
                "手工敏感路径 1": "/phpmyadmin",
                "手工敏感路径 2": "/swagger",
                "手工敏感路径 3": "/api-docs",
            }),
        },
    ]


@app.before_request
def block_blacklisted_ip():
    ip = request.remote_addr or ""
    if ip and is_ip_blocked(ip):
        return ("该 IP 已被 IDS 封禁，禁止继续访问 Flask 站点。", 403)


@app.after_request
def write_access_log(response):
    try:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip = request.remote_addr or "-"
        method = request.method
        path = request.path
        query = build_logged_query()
        ua = request.headers.get("User-Agent", "")
        status = response.status_code
        user = session.get("login_user") or "-"

        line = f"{ts}\t{ip}\t{method}\t{path}\t{query}\t{status}\t{user}\t{ua}\n"

        with open(ACCESS_LOG, "a", encoding="utf-8") as handle:
            handle.write(line)

    except Exception as exc:
        print("写入 access.log 失败：", exc)

    return response


@app.route("/")
def index():
    return render_template(
        "index.html",
        articles=ARTICLES,
        logged_in=is_logged_in(),
        vuln_cards=vuln_cards()[:4],
    )


@app.route("/article/<int:article_id>")
def article(article_id):
    article_data = ARTICLES.get(article_id)
    if article_data is None:
        abort(404)
    comments = ARTICLE_COMMENTS.setdefault(article_id, [])
    return render_template(
        "article.html",
        article_id=article_id,
        article=article_data,
        logged_in=is_logged_in(),
        comments=comments,
    )


@app.route("/article/<int:article_id>/comment", methods=["POST"])
def post_comment(article_id):
    if article_id not in ARTICLES:
        abort(404)

    author = request.form.get("author", "").strip() or "匿名用户"
    body = request.form.get("body", "").strip()
    if body:
        ARTICLE_COMMENTS.setdefault(article_id, []).append(
            {
                "author": author,
                "body": body,
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
    return redirect(url_for("article", article_id=article_id) + "#comments")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if username == DEMO_USER["username"] and password == DEMO_USER["password"]:
        session["login_user"] = username
        session["login_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return redirect(url_for("admin"))

    return render_template("login.html", error="用户名或密码错误")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/admin")
def admin():
    if not is_logged_in():
        return redirect(url_for("login"))

    return render_template(
        "admin.html",
        user=session.get("login_user"),
        login_time=session.get("login_time"),
        article_count=len(ARTICLES),
        articles=ARTICLES,
    )


@app.route("/admin/upload", methods=["GET", "POST"])
def upload_article():
    if not is_logged_in():
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("upload.html", error=None)

    title = request.form.get("title", "").strip()
    file = request.files.get("file")

    if not title:
        return render_template("upload.html", error="标题不能为空")
    if file is None or file.filename.strip() == "":
        return render_template("upload.html", error="请选择要上传的文件")
    if not allowed_file(file.filename):
        return render_template("upload.html", error="文件类型不允许（支持：txt/md/pdf/png/jpg/jpeg）")

    safe_name = secure_filename(file.filename)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    saved_name = f"{ts}_{safe_name}"
    save_path = os.path.join(UPLOAD_FOLDER, saved_name)
    file.save(save_path)

    ext = saved_name.rsplit(".", 1)[1].lower()

    if ext in {"txt", "md"}:
        try:
            with open(save_path, "r", encoding="utf-8") as handle:
                content_text = handle.read()
        except UnicodeDecodeError:
            content_text = "文件编码不是 UTF-8，暂无法直接展示文本内容。请下载查看。"
    else:
        content_text = "该文件类型暂不直接展示内容，请下载查看。"

    new_id = get_next_article_id()
    ARTICLES[new_id] = {
        "title": title,
        "time": datetime.datetime.now().strftime("%Y-%m-%d"),
        "content": content_text,
        "file_name": saved_name,
    }

    return redirect(url_for("article", article_id=new_id))


@app.route("/admin/files/<path:filename>")
def download_file(filename):
    if not is_logged_in():
        return redirect(url_for("login"))
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)


@app.route("/vuln")
@app.route("/lab")
@app.route("/playground")
def vuln_index():
    return render_template(
        "vuln_index.html",
        page_title="Python 博客功能实验区",
        page_desc="基于 Flask 的博客功能实验区，用真实功能点承载可被 IDS 识别的攻击行为，并补充批量测试入口以贴合当前 IDS 的行为聚合规则。",
        cards=vuln_cards(),
        logged_in=is_logged_in(),
    )


@app.route("/admin.php")
@app.route("/admin/exposed")
def admin_php():
    if request.path == "/admin.php":
        return redirect_to_canonical("/admin/exposed")
    examples = make_example_pairs({
        "访问 /.env": "/.env",
        "访问 /.git/config": "/.git/config",
        "访问 /wp-login.php": "/wp-login.php",
        "认证测试入口": "/auth/demo-login",
    })
    return render_template(
        "vuln_demo.html",
        page_title="管理入口暴露演示",
        page_desc="用于演示敏感管理入口、后台页面和常见探测路径。",
        intro="该页面模拟对外暴露的管理入口。直接访问 /admin 或 /admin/exposed 可触发 IDS 对敏感路径和后台探测的检测。",
        form_method="get",
        form_action="/admin/exposed",
        fields=[],
        examples=examples,
        result_title="当前状态",
        result_text="这是一个未做认证保护的后台演示页，仅用于本地 IDS 测试。",
        result_kind="notice",
    )


@app.route("/sqli.php")
@app.route("/search")
def sqli_demo():
    if request.path == "/sqli.php":
        return redirect_to_canonical("/search")
    user_id = request.args.get("q", request.args.get("id", ""))
    query = ""
    if user_id != "":
        query = (
            "SELECT id, title, summary FROM articles "
            "WHERE title LIKE '%" + user_id + "%' OR tags LIKE '%" + user_id + "%'"
        )

    return render_template(
        "vuln_demo.html",
        page_title="博客搜索调试",
        page_desc="用于测试联合查询、布尔注入、时间盲注和数据库高危函数。",
        intro="该页面模拟把搜索关键词直接拼接到 SQL 语句中的调试场景，用于演示博客搜索功能里的 SQL 注入风险。",
        form_method="get",
        form_action="/search",
        fields=[
            {
                "label": "搜索关键词",
                "name": "q",
                "type": "text",
                "value": user_id,
                "placeholder": "flask 或 1' UNION SELECT null,user(),database() --",
            }
        ],
        examples=make_example_pairs({
            "布尔注入": "/search?q=1%27+OR+%271%27%3D%271",
            "联合查询": "/search?q=1+UNION+SELECT+null%2Cuser%28%29%2Cdatabase%28%29+--",
            "时间盲注": "/search?q=1%27%3Bwaitfor+delay+%270%3A0%3A5%27--",
            "LOAD_FILE": "/search?q=1%27+UNION+SELECT+load_file%28%27%2Fetc%2Fpasswd%27%29%2Cnull%2Cnull--",
            "xp_cmdshell": "/search?q=1%27%3Bexec+master..xp_cmdshell+%27whoami%27--",
        }),
        result_title="拼接后的危险 SQL",
        result_text=query if query else None,
        result_kind="code",
    )


@app.route("/xss.php")
@app.route("/comments/preview")
def xss_demo():
    if request.path == "/xss.php":
        return redirect_to_canonical("/comments/preview")
    name = request.args.get("content", request.args.get("name", ""))
    preview = f"评论预览：{name}" if name else ""

    return render_template(
        "vuln_demo.html",
        page_title="评论预览",
        page_desc="用于测试 script、事件属性、javascript 协议等 XSS 特征。",
        intro="该页面模拟博客评论预览功能，会把评论内容直接输出到 HTML 中，不做任何转义，可用于演示反射型 XSS。",
        form_method="get",
        form_action="/comments/preview",
        fields=[
            {
                "label": "评论内容",
                "name": "content",
                "type": "text",
                "value": name,
                "placeholder": "<script>alert(1)</script>",
            }
        ],
        examples=make_example_pairs({
            "script 标签": "/comments/preview?content=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            "事件型 XSS": "/comments/preview?content=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E",
            "javascript 协议": "/comments/preview?content=javascript%3Aalert%281%29",
            "SVG onload": "/comments/preview?content=%3Csvg+onload%3Dalert%281%29%3E",
        }),
        result_title="危险输出结果",
        result_text="下面内容未经过滤，浏览器会直接解析：" if preview else None,
        result_kind="notice",
        unsafe_preview=preview,
    )


@app.route("/shell.php")
@app.route("/rce.php")
@app.route("/cmd.php")
@app.route("/admin/debug/exec")
def shell_demo():
    if request.path in {"/shell.php", "/rce.php", "/cmd.php"}:
        return redirect_to_canonical("/admin/debug/exec")
    cmd = request.args.get("cmd", "")
    output = None
    if cmd != "":
        try:
            completed = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=2,
            )
            output = completed.stdout + completed.stderr
            output = output.strip() or "[命令已执行，但没有输出]"
        except Exception as exc:
            output = f"[命令执行失败] {exc}"

    return render_template(
        "vuln_demo.html",
        page_title="后台诊断页",
        page_desc="用于测试 cmd 参数、危险命令词和执行路径。",
        intro="该页面模拟后台运维诊断功能，把 cmd 参数直接交给系统 Shell 执行，可用于演示命令执行和 RCE。",
        form_method="get",
        form_action="/admin/debug/exec",
        fields=[
            {
                "label": "系统命令",
                "name": "cmd",
                "type": "text",
                "value": cmd,
                "placeholder": "whoami 或 uname -a",
            }
        ],
        examples=make_example_pairs({
            "执行 whoami": f"{request.path}?cmd=whoami",
            "执行 id": f"{request.path}?cmd=id",
            "执行 uname -a": f"{request.path}?cmd=uname+-a",
            "下载执行特征": f"{request.path}?cmd=curl+http://example.com",
        }),
        result_title="执行结果",
        result_text=output,
        result_kind="code",
    )


@app.route("/upload.php", methods=["GET", "POST"])
@app.route("/admin/media/upload", methods=["GET", "POST"])
def vuln_upload():
    if request.path == "/upload.php":
        return redirect_to_canonical("/admin/media/upload")
    filename = request.args.get("filename", "").strip() or request.form.get("filename_hint", "").strip()
    upload_file = request.files.get("file")
    message = None
    saved_path = None

    if request.method == "POST" and upload_file and upload_file.filename:
        requested_name = filename or upload_file.filename
        saved_name = safe_vuln_filename(requested_name)
        save_path = os.path.join(VULN_UPLOAD_FOLDER, saved_name)
        upload_file.save(save_path)
        saved_path = f"/uploads/{saved_name}"
        message = f"上传成功，文件已保存到 {saved_path}"

    return render_template(
        "vuln_upload.html",
        page_title="媒体上传中心",
        page_desc="用于演示危险脚本扩展名、双扩展和上传后访问。",
        intro="该页面模拟博客后台的媒体上传功能。提交时会把危险文件名同步到查询串中，便于 IDS 识别上传类攻击。",
        filename_value=filename,
        examples=make_example_pairs({
            "访问上传目录": "/uploads/",
            "访问上传后的脚本": "/uploads/media.jsp?cmd=whoami",
        }),
        message=message,
        saved_path=saved_path,
    )


@app.route("/uploads/")
def vuln_upload_listing():
    items = []
    for name in sorted(os.listdir(VULN_UPLOAD_FOLDER)):
        abs_path = os.path.join(VULN_UPLOAD_FOLDER, name)
        if os.path.isfile(abs_path):
            items.append({
                "name": name,
                "url": f"/uploads/{name}",
            })

    return render_template(
        "vuln_listing.html",
        page_title="上传目录浏览",
        page_desc="用于演示上传后访问、目录暴露和脚本访问。",
        intro="下面列出博客功能实验区里已上传的文件。点击后可以直接访问，若文件名带脚本扩展且传入 cmd 参数，还可以模拟上传后访问与 WebShell 执行链路。",
        items=items,
    )


@app.route("/uploads/<path:filename>")
def vuln_uploaded_file(filename):
    safe_name = safe_vuln_filename(filename)
    file_path = os.path.join(VULN_UPLOAD_FOLDER, safe_name)
    if not os.path.isfile(file_path):
        abort(404)

    cmd = request.args.get("cmd", "")
    if cmd and looks_script_like(safe_name):
        try:
            completed = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=2,
            )
            output = (completed.stdout + completed.stderr).strip() or "[命令已执行，但没有输出]"
        except Exception as exc:
            output = f"[命令执行失败] {exc}"
        return Response(output, mimetype="text/plain")

    return send_from_directory(VULN_UPLOAD_FOLDER, safe_name, as_attachment=False)


@app.route("/lfi.php")
@app.route("/admin/files/view")
def lfi_demo():
    if request.path == "/lfi.php":
        return redirect_to_canonical("/admin/files/view")
    file_target = request.args.get("file", request.args.get("page", ""))
    output = None

    if file_target:
        try:
            output = short_text(read_path_like(file_target), 4000)
        except Exception as exc:
            output = f"读取失败或文件不存在：{file_target}\n{exc}"

    return render_template(
        "vuln_demo.html",
        page_title="文件预览 / 导入调试",
        page_desc="用于演示路径穿越、文件包装器和敏感文件读取。",
        intro="该页面模拟后台文件预览和内容导入功能，将 file / page 参数直接用于读取文件内容，可用于演示 ../、php://filter、file://、data:// 等危险读取场景。",
        form_method="get",
        form_action="/admin/files/view",
        fields=[
            {
                "label": "文件路径",
                "name": "file",
                "type": "text",
                "value": file_target,
                "placeholder": "../../../../etc/passwd 或 php://filter/convert.base64-encode/resource=app.py",
            }
        ],
        examples=make_example_pairs({
            "路径穿越读取 /etc/passwd": "/admin/files/view?file=../../../../etc/passwd",
            "读取 Win.ini": "/admin/files/view?file=..%5C..%5Cwindows%5Cwin.ini",
            "读取 app.py（base64）": "/admin/files/view?file=php://filter/convert.base64-encode/resource=app.py",
            "file:// 读取 .env": query_link("/admin/files/view", {"file": demo_file_uri(".env")}),
        }),
        result_title="读取结果",
        result_text=output,
        result_kind="code",
    )


@app.route("/proxy.php")
@app.route("/admin/fetch-preview")
def proxy_demo():
    if request.path == "/proxy.php":
        return redirect_to_canonical("/admin/fetch-preview")
    target = request.args.get("url", request.args.get("target", ""))
    result = None

    if target:
        try:
            result = short_text(fetch_remote_resource(target), 2200)
        except HTTPError as exc:
            result = f"代理请求失败：HTTP {exc.code}\n{exc.reason}"
        except URLError as exc:
            result = f"代理请求失败：{exc.reason}"
        except Exception as exc:
            result = f"代理请求失败：{exc}"

    admin_url = current_base_url() + "/admin/exposed"
    return render_template(
        "vuln_demo.html",
        page_title="远程内容预览",
        page_desc="用于模拟服务器端请求伪造（SSRF）场景。",
        intro="该页面模拟后台远程封面/内容预览功能，会直接拉取用户提供的 URL，可用于演示内网探测、云元数据访问和危险协议访问。",
        form_method="get",
        form_action="/admin/fetch-preview",
        fields=[
            {
                "label": "目标 URL",
                "name": "url",
                "type": "text",
                "value": target,
                "placeholder": admin_url,
            }
        ],
        examples=make_example_pairs({
            "访问本机 admin": query_link("/admin/fetch-preview", {"url": admin_url}),
            "访问云元数据": "/admin/fetch-preview?url=http://169.254.169.254/latest/meta-data/",
            "dict 协议": "/admin/fetch-preview?url=dict://127.0.0.1:6379/dbsize",
            "file 协议读取 .env": query_link("/admin/fetch-preview", {"url": demo_file_uri(".env")}),
        }),
        result_title="代理返回",
        result_text=result,
        result_kind="code",
    )


@app.route("/xxe.php", methods=["GET", "POST"])
@app.route("/admin/xml-import", methods=["GET", "POST"])
def xxe_demo():
    if request.path == "/xxe.php":
        return redirect_to_canonical("/admin/xml-import")
    xml = request.form.get("xml", request.args.get("xml", ""))
    result = None

    if xml:
        result = short_text(simulate_xxe(xml), 3200)

    return render_template(
        "vuln_demo.html",
        page_title="XML 导入中心",
        page_desc="用于测试 XML 外部实体注入和危险 DTD 解析。",
        intro="该页面模拟博客后台的 XML 数据导入功能，会处理用户提交的 XML，并模拟解析 SYSTEM / PUBLIC 外部实体。",
        form_method="post",
        form_action="/admin/xml-import",
        form_id="xxe-form",
        fields=[
            {
                "label": "XML 内容",
                "name": "xml",
                "type": "textarea",
                "value": xml,
                "placeholder": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            }
        ],
        examples=make_example_pairs({
            "读取 /etc/passwd": "/admin/xml-import?xml=%3C!DOCTYPE%20foo%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file:///etc/passwd%22%3E%5D%3E%3Cfoo%3E%26xxe%3B%3C/foo%3E",
            "PUBLIC 外部实体": "/admin/xml-import?xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20sp%20PUBLIC%20%22a%22%20%22file:///etc/passwd%22%3E%5D%3E%3Cr%3E%26sp%3B%3C/r%3E",
        }),
        result_title="解析结果",
        result_text=result,
        result_kind="code",
        page_script="""
document.getElementById("xxe-form").addEventListener("submit", function () {
  const xmlField = document.getElementById("field-xml");
  const params = new URLSearchParams(window.location.search);
  params.set("xml", xmlField.value);
  this.action = "/admin/xml-import?" + params.toString();
});
""",
    )


@app.route("/ssti.php")
@app.route("/admin/template-preview")
def ssti_demo():
    if request.path == "/ssti.php":
        return redirect_to_canonical("/admin/template-preview")
    template = request.args.get("template", request.args.get("tpl", ""))
    output = render_ssti(template) if template else None

    return render_template(
        "vuln_demo.html",
        page_title="模板预览",
        page_desc="用于模拟服务端模板表达式被直接执行的危险场景。",
        intro="该页面模拟后台模板预览功能，会把 {{ ... }} 或 ${ ... } 里的表达式直接交给 Jinja 模板渲染，可用于演示模板注入。",
        form_method="get",
        form_action="/admin/template-preview",
        fields=[
            {
                "label": "模板内容",
                "name": "template",
                "type": "textarea",
                "value": template,
                "placeholder": "{{7*7}} 或 ${7*7}",
            }
        ],
        examples=make_example_pairs({
            "Jinja 风格": "/admin/template-preview?template=%7B%7B7*7%7D%7D",
            "EL 风格": "/admin/template-preview?template=%24%7B7*7%7D",
            "读取配置项": "/admin/template-preview?template=%7B%7Bconfig.items%28%29%7D%7D",
            "角色属性": "/admin/template-preview?template=%7B%7Bprofile.role%7D%7D",
        }),
        result_title="渲染结果",
        result_text=output,
        result_kind="code",
    )


@app.route("/nosqli.php")
@app.route("/admin/member-filter")
def nosqli_demo():
    if request.path == "/nosqli.php":
        return redirect_to_canonical("/admin/member-filter")
    payload_filter = request.args.get("filter", "")
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    result = None

    if payload_filter or username or password:
        if payload_filter:
            try:
                decoded = json.loads(payload_filter)
                result = json.dumps(decoded, ensure_ascii=False, indent=2)
            except json.JSONDecodeError:
                result = payload_filter
        else:
            result = json.dumps(
                {
                    "username": username,
                    "password": password,
                },
                ensure_ascii=False,
                indent=2,
            )

    return render_template(
        "vuln_demo.html",
        page_title="用户筛选调试",
        page_desc="用于测试 MongoDB 风格的查询操作符注入。",
        intro="该页面模拟后台成员筛选功能把 filter JSON 或用户名、密码条件直接拼接进 MongoDB 查询的场景。",
        form_method="get",
        form_action="/admin/member-filter",
        fields=[
            {
                "label": "filter JSON",
                "name": "filter",
                "type": "textarea",
                "value": payload_filter,
                "placeholder": '{"$where":"this.password.length>0"}',
            },
            {
                "label": "username",
                "name": "username",
                "type": "text",
                "value": username,
                "placeholder": '{"$ne":null}',
            },
            {
                "label": "password",
                "name": "password",
                "type": "text",
                "value": password,
                "placeholder": '{"$regex":".*"}',
            },
        ],
        examples=make_example_pairs({
            "$where 条件注入": "/admin/member-filter?filter=%7B%22%24where%22%3A%22this.password.length%3E0%22%7D",
            "$ne 绕过": "/admin/member-filter?username=%7B%22%24ne%22%3Anull%7D&password=%7B%22%24ne%22%3Anull%7D",
            "$regex 枚举": "/admin/member-filter?filter=%7B%22name%22%3A%7B%22%24regex%22%3A%22.*%22%7D%7D",
        }),
        result_title="模拟查询",
        result_text=result,
        result_kind="code",
    )


@app.route("/redirect.php")
@app.route("/go")
def redirect_demo():
    if request.path == "/redirect.php":
        return redirect_to_canonical("/go")
    next_url = request.args.get("next", request.args.get("redirect", ""))
    go = request.args.get("go", "")
    if next_url and go == "1":
        return redirect(next_url)

    return render_template(
        "vuln_demo.html",
        page_title="跳转设置",
        page_desc="用于测试 next / redirect 等跳转参数。",
        intro="该页面模拟登录后跳转设置，会把 next 参数直接交给 Location 头。为了方便演示，默认只展示跳转目标；当 go=1 时会真的执行跳转。",
        form_method="get",
        form_action="/go",
        fields=[
            {
                "label": "跳转目标",
                "name": "next",
                "type": "text",
                "value": next_url,
                "placeholder": "http://example.com",
            },
            {
                "label": "",
                "name": "go",
                "type": "hidden",
                "value": "1",
                "placeholder": "",
            },
        ],
        examples=make_example_pairs({
            "跳转到外站": "/go?next=http://example.com&go=1",
            "双斜杠跳转": "/go?next=//evil.example.com&go=1",
            "带 CRLF": "/go?next=http://example.com%250d%250aX-Test%3A1",
        }),
        result_title="当前跳转目标",
        result_text=next_url if next_url else None,
        result_kind="code",
    )


@app.route("/tamper.php")
@app.route("/checkout/review")
@app.route("/admin/order-review")
def tamper_demo():
    if request.path == "/tamper.php":
        return redirect_to_canonical("/admin/order-review")

    payload = {}
    for key in ("uid", "user_id", "role", "is_admin", "price", "amount", "discount", "quantity", "balance", "status"):
        value = request.values.get(key, "")
        if value != "":
            payload[key] = value

    result = json.dumps(payload, ensure_ascii=False, indent=2) if payload else None
    return render_template(
        "vuln_demo.html",
        page_title="订单确认 / 权限参数调试",
        page_desc="用于模拟价格、数量、权限与账户余额等关键业务参数被直接信任的场景。",
        intro="该页面模拟后台订单确认与权限同步接口，会直接接收 uid、role、is_admin、price、amount、discount、quantity、balance、status 等参数，可用于演示参数篡改与业务字段攻击。",
        form_method="get",
        form_action="/admin/order-review",
        fields=[
            {"label": "用户 ID", "name": "uid", "type": "text", "value": request.values.get("uid", ""), "placeholder": "1001"},
            {"label": "角色", "name": "role", "type": "text", "value": request.values.get("role", ""), "placeholder": "user 或 admin"},
            {"label": "管理员标记", "name": "is_admin", "type": "text", "value": request.values.get("is_admin", ""), "placeholder": "0 或 1"},
            {"label": "单价", "name": "price", "type": "text", "value": request.values.get("price", ""), "placeholder": "199.00"},
            {"label": "订单金额", "name": "amount", "type": "text", "value": request.values.get("amount", ""), "placeholder": "398.00"},
            {"label": "折扣", "name": "discount", "type": "text", "value": request.values.get("discount", ""), "placeholder": "0"},
            {"label": "数量", "name": "quantity", "type": "text", "value": request.values.get("quantity", ""), "placeholder": "2"},
            {"label": "账户余额", "name": "balance", "type": "text", "value": request.values.get("balance", ""), "placeholder": "300.00"},
            {"label": "状态", "name": "status", "type": "text", "value": request.values.get("status", ""), "placeholder": "pending / vip / paid"},
        ],
        examples=make_example_pairs({
            "价格篡改": "/admin/order-review?uid=1001&price=0.01&amount=0.01&quantity=99",
            "权限提权": "/admin/order-review?uid=1001&role=admin&is_admin=1&status=vip",
            "余额覆盖": "/admin/order-review?uid=1001&balance=999999&discount=100&status=paid",
            "复合参数篡改": "/admin/order-review?uid=1001&role=admin&is_admin=1&price=0.01&amount=0.01&discount=100&quantity=50",
        }),
        result_title="接收到的业务参数",
        result_text=result,
        result_kind="code",
    )


@app.route("/scanner.php")
@app.route("/admin/traffic-runner")
def traffic_runner():
    if request.path == "/scanner.php":
        return redirect_to_canonical("/admin/traffic-runner")

    profiles = {
        "sensitive": [
            {"label": "GET /.env", "url": "/.env", "method": "GET"},
            {"label": "GET /phpmyadmin", "url": "/phpmyadmin", "method": "GET"},
            {"label": "GET /swagger", "url": "/swagger", "method": "GET"},
            {"label": "GET /api-docs", "url": "/api-docs", "method": "GET"},
        ],
        "scanner": [
            {"label": "HEAD /swagger", "url": "/swagger", "method": "HEAD"},
            {"label": "OPTIONS /api-docs", "url": "/api-docs", "method": "OPTIONS"},
            {"label": "GET /vendor/phpunit/eval-stdin.php", "url": "/vendor/phpunit/eval-stdin.php", "method": "GET"},
            {"label": "GET /manager/html", "url": "/manager/html", "method": "GET"},
        ],
        "bruteforce": [
            {
                "label": "POST admin/wrongpass1",
                "url": "/auth/demo-login?login=admin&pwd=wrongpass1",
                "method": "POST",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "login=admin&pwd=wrongpass1",
            },
            {
                "label": "POST admin/wrongpass2",
                "url": "/auth/demo-login?login=admin&pwd=wrongpass2",
                "method": "POST",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "login=admin&pwd=wrongpass2",
            },
            {
                "label": "POST admin/wrongpass3",
                "url": "/auth/demo-login?login=admin&pwd=wrongpass3",
                "method": "POST",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "login=admin&pwd=wrongpass3",
            },
            {
                "label": "POST admin/wrongpass4",
                "url": "/auth/demo-login?login=admin&pwd=wrongpass4",
                "method": "POST",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "login=admin&pwd=wrongpass4",
            },
        ],
        "combo": [
            {"label": "SQLi", "url": "/search?q=1+UNION+SELECT+load_file%28%27%2Fetc%2Fpasswd%27%29%2Cnull%2Cnull--", "method": "GET"},
            {"label": "LFI", "url": "/admin/files/view?file=../../../../etc/passwd", "method": "GET"},
            {"label": "SSRF", "url": query_link("/admin/fetch-preview", {"url": demo_file_uri(".env")}), "method": "GET"},
            {"label": "RCE", "url": "/admin/debug/exec?cmd=whoami", "method": "GET"},
        ],
    }

    extra_html = """
<h2>一键流量生成</h2>
<p>点击下面按钮后，页面会连续发起多次请求，用来更稳定地触发当前 IDS 的敏感路径聚合、扫描方法识别、暴力破解与复合攻击链判断。</p>
<div class="examples">
  <button class="secondary" type="button" data-profile="sensitive">触发敏感路径探测</button>
  <button class="secondary" type="button" data-profile="scanner">触发扫描方法</button>
  <button class="secondary" type="button" data-profile="bruteforce">触发暴力破解</button>
  <button class="secondary" type="button" data-profile="combo">触发组合攻击链</button>
</div>
<pre id="runner-output" style="margin-top:16px">点击按钮后，这里会显示每一步请求的返回状态。</pre>
"""

    page_script = f"""
const profiles = {json.dumps(profiles, ensure_ascii=False)};
const output = document.getElementById("runner-output");

async function runProfile(name) {{
  const steps = profiles[name] || [];
  const tracePrefix = `${{Date.now()}}_${{name}}`;
  output.textContent = `开始执行 ${{name}}，共 ${{steps.length}} 个请求...`;
  const lines = [];

  for (let index = 0; index < steps.length; index += 1) {{
    const step = steps[index];
    const separator = step.url.includes("?") ? "&" : "?";
    const trace = `${{tracePrefix}}_${{index + 1}}`;
    const finalUrl = `${{step.url}}${{separator}}trace=${{encodeURIComponent(trace)}}`;
    const options = {{
      method: step.method || "GET",
      credentials: "same-origin",
      headers: step.headers || {{}},
    }};
    if (step.body) {{
      options.body = step.body + `&trace=${{encodeURIComponent(trace)}}`;
    }}
    try {{
      const response = await fetch(finalUrl, options);
      lines.push(`[${{index + 1}}/${{steps.length}}] ${{step.label}} -> HTTP ${{response.status}}`);
    }} catch (error) {{
      lines.push(`[${{index + 1}}/${{steps.length}}] ${{step.label}} -> ERROR: ${{error}}`);
    }}
    output.textContent = lines.join("\\n");
    await new Promise((resolve) => setTimeout(resolve, 220));
  }}

  output.textContent = lines.join("\\n") + "\\n\\n已完成，请回到 IDS 页面查看最新告警。";
}}

document.querySelectorAll("[data-profile]").forEach((button) => {{
  button.addEventListener("click", () => runProfile(button.getAttribute("data-profile")));
}});
"""

    return render_template(
        "vuln_demo.html",
        page_title="批量流量生成器",
        page_desc="用于一键生成聚合型攻击流量，便于验证当前 IDS 对时间窗口与复合攻击链的判断。",
        intro="该页面不直接执行漏洞，而是自动按顺序请求多个敏感路径、扫描方法、认证接口和复合攻击入口，让你更容易验证现在 IDS 的行为级规则。",
        fields=[],
        examples=make_example_pairs({
            "手工打开 /.env": "/.env",
            "手工打开 /phpmyadmin": "/phpmyadmin",
            "手工打开 /auth/demo-login": "/auth/demo-login",
            "手工打开 /admin/order-review": "/admin/order-review",
        }),
        extra_html=extra_html,
        page_script=page_script,
    )


@app.route("/login.php", methods=["GET", "POST"])
@app.route("/auth/demo-login", methods=["GET", "POST"])
def vuln_login():
    if request.path == "/login.php":
        return redirect_to_canonical("/auth/demo-login")
    login_name = request.form.get("login", request.args.get("login", ""))
    pwd = request.form.get("pwd", request.args.get("pwd", ""))
    submitted = request.method == "POST"
    result = None

    if submitted:
        result = f"登录失败：用户 {login_name or '-'} 的密码验证未通过。"

    return render_template(
        "vuln_demo.html",
        page_title="认证测试",
        page_desc="用于模拟匿名用户重复提交认证请求的场景。",
        intro="该页面模拟博客认证接口。为了让日志记录器拿到认证参数，提交时会把表单里的 login 和 pwd 同步到 URL 查询串，再以 POST 方式提交。",
        form_method="post",
        form_action="/auth/demo-login",
        form_id="vuln-login-form",
        fields=[
            {
                "label": "用户名",
                "name": "login",
                "type": "text",
                "value": login_name,
                "placeholder": "admin",
            },
            {
                "label": "密码",
                "name": "pwd",
                "type": "text",
                "value": pwd,
                "placeholder": "admin123",
            },
        ],
        examples=make_example_pairs({
            "POST 登录 admin/admin123": "/auth/demo-login?login=admin&pwd=admin123",
            "POST 登录 test/wrongpass": "/auth/demo-login?login=test&pwd=wrongpass",
            "扫描器登录尝试": "/auth/demo-login?login=admin&pwd=wrongpass&tool=sqlmap",
        }),
        result_title="登录结果",
        result_text=result,
        result_kind="notice",
        page_script="""
document.getElementById("vuln-login-form").addEventListener("submit", function () {
  const loginField = document.getElementById("field-login");
  const pwdField = document.getElementById("field-pwd");
  const params = new URLSearchParams(window.location.search);
  params.set("login", loginField.value);
  params.set("pwd", pwdField.value);
  this.action = "/auth/demo-login?" + params.toString();
});
""",
    )


@app.route("/.env")
def env_file():
    return Response(ENV_CONTENT, mimetype="text/plain")


@app.route("/.git/config")
def git_config():
    return Response(GIT_CONFIG_CONTENT, mimetype="text/plain")


@app.route("/backup.sql")
def backup_sql():
    return Response(BACKUP_SQL_CONTENT, mimetype="text/plain")


@app.route("/phpmyadmin")
def phpmyadmin_probe():
    return Response("phpMyAdmin 4.9.0 demo login", mimetype="text/plain")


@app.route("/wp-login.php")
def wp_login_probe():
    return Response("WordPress login page placeholder", mimetype="text/plain")


@app.route("/swagger")
def swagger_probe():
    return Response("<html><body><h1>Swagger UI</h1></body></html>", mimetype="text/html")


@app.route("/api-docs")
def api_docs_probe():
    return Response(json.dumps({"openapi": "3.0.0", "info": {"title": "Demo API"}}), mimetype="application/json")


@app.route("/actuator")
def actuator_probe():
    return Response(json.dumps({"status": "UP", "components": {"db": "UP"}}), mimetype="application/json")


@app.route("/vendor/phpunit")
@app.route("/vendor/phpunit/eval-stdin.php")
def phpunit_probe():
    return Response("PHPUnit eval-stdin placeholder", mimetype="text/plain")


@app.route("/manager/html")
def tomcat_manager_probe():
    return Response("<html><body><h1>Tomcat Web Application Manager</h1></body></html>", mimetype="text/html")


if __name__ == "__main__":
    debug_mode = os.environ.get("TARGET_SITE_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    target_port = int(os.environ.get("TARGET_SITE_PORT", "15002") or "15002")
    app.run(host="127.0.0.1", port=target_port, debug=debug_mode, use_reloader=False, threaded=True)
