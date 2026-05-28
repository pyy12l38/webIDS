vuln_php_site
│
├── bootstrap.php       # Nginx / PHP-FPM 友好的公共初始化层
├── index.php           # 漏洞导航首页
├── admin.php           # 后台入口暴露
├── login.php           # 认证 / 暴力破解演示
├── sqli.php            # SQL 注入
├── xss.php             # XSS
├── shell.php           # 命令执行
├── cmd.php             # 命令执行别名入口
├── rce.php             # 命令执行别名入口
├── upload.php          # 文件上传 / WebShell
├── lfi.php             # 文件读取 / 路径穿越
├── proxy.php           # SSRF
├── xxe.php             # XXE / XML 注入
├── ssti.php            # SSTI / 模板注入
├── nosqli.php          # NoSQL 注入
├── redirect.php        # 开放重定向
├── router.php          # 本地 php -S 开发路由器
├── logger.php          # 本地开发模式日志记录器
├── deploy/nginx-vuln-site.conf   # Nginx 部署示例
│
├── .env                # 敏感配置文件演示
├── .git/config         # Git 配置泄露演示
├── backup.sql          # 备份文件泄露演示
├── uploads/            # 上传目录
└── logs/access.log     # 访问日志

部署说明

1. 本地开发模式
- 使用 `php -S 127.0.0.1:8080 router.php`
- `router.php + logger.php` 负责把静态文件和动态 PHP 请求都记录到 `logs/access.log`

2. Nginx + PHP-FPM 部署模式
- 建议直接使用 `deploy/nginx-vuln-site.conf`
- 由 Nginx 统一记录 `access.log`
- `bootstrap.php` 负责动态页面的公共初始化、代理头兼容和 IDS 封禁页返回

3. 说明
- 本站保留 `.env`、`.git/config`、`backup.sql` 等敏感资源暴露能力，仅用于 IDS 演示
- 若切换到 Nginx 日志，请把 IDS Agent 指向 Nginx 生成的 `logs/access.log`
