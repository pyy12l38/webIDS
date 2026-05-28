# Standalone Honeypot

这是一个独立于当前项目其他模块的轻量 Web 蜜罐。

它不依赖现有 `ids_site`、`target_site` 或 `vuln_php_site`，只需要 Flask 就能运行。

## 功能

- 假后台登录页：`/admin/login`
- 假 `phpMyAdmin`：`/phpmyadmin`
- 假 `WordPress` 登录：`/wp-login.php`
- 假 Web Shell：`/shell`
- 假上传中心：`/upload`
- 假调试代理：`/api/proxy`
- 假敏感文件：`/.env`、`/.git/config`、`/backup.zip`
- 隐藏控制台：`/__console__?token=lab`

## 日志

运行后会自动生成：

- `logs/access.log`
- `logs/captures.jsonl`
- `uploads/`

其中：

- `access.log` 记录所有访问
- `captures.jsonl` 只记录更有价值的交互，如口令、命令、URL、上传文件名、敏感路径探测

## 启动

在项目根目录执行：

```bash
python3 standalone_honeypot/app.py
```

默认端口：

- `8091`

可选环境变量：

```bash
export HONEYPOT_PORT=8091
export HONEYPOT_DEBUG=1
export HONEYPOT_CONSOLE_TOKEN='change-me'
python3 standalone_honeypot/app.py
```

## 访问示例

- 首页：<http://127.0.0.1:8091/>
- 登录陷阱：<http://127.0.0.1:8091/admin/login>
- 命令陷阱：<http://127.0.0.1:8091/shell?cmd=whoami>
- SSRF 陷阱：<http://127.0.0.1:8091/api/proxy?url=http://169.254.169.254/latest/meta-data/>
- 控制台：<http://127.0.0.1:8091/__console__?token=lab>

## 注意

- 这是演示型蜜罐，不适合直接当高强度生产蜜罐使用
- 上传文件会保存到本地 `uploads/`，不会执行
- 如果要放公网，建议先改 `HONEYPOT_CONSOLE_TOKEN`
