# 项目说明

本项目是一个面向 Web 安全场景的毕业设计实验平台，当前主系统已经收口为 **Proxy 单模式 Web IDS**。  
所有被检测站点的外部请求先进入 IDS 代理网关，再转发到真实后端，IDS 在代理入口统一采集请求、执行规则检测、生成告警并在前端展示。

## 当前架构

- `target_site`：Python 博客后端
- `vuln_php_site`：PHP 漏洞测试后端
- `ids_site`：Flask 编写的 IDS 平台与 Proxy 网关


## 当前主系统运行链路

1. 用户访问站点外部入口端口，例如 `5002` 或 `8080`
2. 请求先到 `ids_site/proxy_gateway.py`
3. 代理网关将请求转发到真实后端端口
4. 代理网关同步把请求事件上报到 `ids_site/app.py` 的 `/api/collect`
5. IDS 后端执行规则检测、攻击链分析、威胁分级与响应判定
6. 前端页面轮询 `/api/events` 和其他统计接口进行展示

## 项目结构

```text
.
├── run.py
├── requirements.txt
├── rebuild_venv.sh
├── target_site/
│   ├── app.py
│   ├── templates/
│   └── uploads/
├── ids_site/
│   ├── app.py
│   ├── proxy_gateway.py
│   ├── sqlite_store.py
│   ├── blocklist.py
│   ├── defense_settings.py
│   ├── source_config.py
│   ├── templates/
│   └── static/
├── vuln_php_site/
│   ├── index.php
│   ├── sqli.php
│   ├── xss.php
│   ├── rce.php
│   ├── upload.php
│   ├── lfi.php
│   ├── proxy.php
│   ├── xxe.php
│   ├── ssti.php
│   ├── nosqli.php
│   ├── redirect.php
│   ├── login.php
│   ├── common.php
└──   └── deploy/
```

## 运行环境

- Python 3.11 推荐
- PHP CLI
- Nginx
- PHP-FPM

## 安装依赖

建议使用虚拟环境：

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

如果本地虚拟环境混乱，可以执行：

```bash
./rebuild_venv.sh
```

## 启动项目

在项目根目录执行：

```bash
python run.py
```

默认访问地址：

- IDS 平台：<http://127.0.0.1:5001>
- Python 博客对外入口：<http://127.0.0.1:5002>
- PHP 漏洞站对外入口：<http://127.0.0.1:8080>

## 当前默认端口说明

当前默认两站点都使用 **Proxy 单模式**：

- `Flask博客`
  - 外部监听端口：`5002`
  - 真实后端端口：`15002`
- `PHP漏洞站`
  - 外部监听端口：`8080`
  - 真实后端端口：`18080`

也就是说，浏览器访问的是外部监听端口，真实应用运行在内部后端端口，由 IDS 代理网关统一转发。

## 如何新增一个站点

当前新增站点采用 **Proxy 单模式接入**，最简操作如下：

1. 启动 IDS 平台后，打开 <http://127.0.0.1:5001>
2. 进入 `系统设置 -> 检测站点`
3. 点击 `＋ 代理站点` 或 `＋ 添加站点`
4. 在快速向导中至少填写：
   - `监听端口`
   - `后端端口`
   - `域名 / Host` 可选
5. 点击 `自动生成接入配置`
6. 再点击创建或保存

### 新增站点时要注意

- **监听端口**：外部用户真正访问的端口，由 IDS 代理网关占用
- **后端端口**：真实业务程序监听的内部端口
- 如果一个网站原来直接跑在 `5003`，而你想让 IDS 接管这个端口：
  - 先把业务后端改到另一个内部端口，例如 `15003`
  - 再在 IDS 里新增站点：
    - 监听端口：`5003`
    - 后端端口：`15003`

### 举例

假设你新增一个本地 Flask 站点：

- 原来业务直接监听：`127.0.0.1:5003`

你应该改成：

- 业务后端监听：`127.0.0.1:15003`
- IDS 代理监听：`0.0.0.0:5003`

在 IDS 页面中填写：

- 站点名称：可留空自动生成
- 监听端口：`5003`
- 后端端口：`15003`
- 域名 / Host：可留空或写 `127.0.0.1`

保存后，访问 `http://127.0.0.1:5003` 就会先经过 IDS。

## 当前 IDS 已覆盖的主要攻击类型

- SQL 注入
- XSS
- 命令执行 / RCE
- 文件上传 / WebShell
- 路径穿越 / 敏感文件访问
- 扫描探测 / 目录爆破
- 认证攻击 / 暴力破解
- 参数篡改 / 业务参数攻击
- SSRF
- XXE / XML 注入
- SSTI / 模板表达式注入
- NoSQL 注入
- 开放重定向
- 协议与请求异常

规则引擎支持：

- 主攻击类型 `attack_type`
- 次级攻击类型 `secondary_attack_types`
- 危险等级 `level`
- 命中信号 `matched_signals`
- 攻击链 `attack_chain`
- 基于配置的高危自动封禁

## 各模块说明

### 1. `target_site`

Flask 编写的 Python 博客后端，用于产生正常访问流量和部分攻击测试请求。

### 2. `ids_site`

Flask 编写的 IDS 平台，负责：

- Proxy 入口采集
- 规则检测与攻击分类
- 威胁等级判定
- 攻击链分析
- 白名单与封禁管理
- 前端分页、筛选、详情展示

### 3. `vuln_php_site`

PHP 漏洞测试后端，用于生成典型 Web 攻击流量。当前主要页面包括：

- `sqli.php`
- `xss.php`
- `rce.php`
- `upload.php`
- `lfi.php`
- `proxy.php`
- `xxe.php`
- `ssti.php`
- `nosqli.php`
- `redirect.php`
- `login.php`

### 4. `ml_lab`

机器学习实验目录，与主 IDS 运行链路解耦，用于日志分类模型训练与评估。

## 机器学习模块当前接入方式

当前主 IDS 采用：

- `规则引擎主判`
- `机器学习辅助分类`
- `融合结果单独记录`

默认情况下，机器学习模块 **不会直接覆盖首页统计和主攻击类型**，而是为每条事件补充以下字段：

- `rule_attack_type` / `rule_level`
- `ml_attack_type` / `ml_confidence` / `ml_top3`
- `fusion_attack_type` / `fusion_level`
- `decision_source`
- `fusion_reason`

也就是说，第一版接入目标是：

1. 先把在线推理链路打通
2. 先让 ML 结果能真实入库、展示、复盘
3. 默认不破坏现有规则检测稳定性

如果后续确认效果稳定，可以在系统设置或接口配置中开启：

- `enable_ml_assist`
- `ml_allow_ml_only_alerts`
- `ml_allow_fusion_promotion`
- `ml_apply_fusion_as_primary`

其中：

- `enable_ml_assist=false`：完全关闭 ML 推理
- `ml_apply_fusion_as_primary=false`：即使融合完成，也仍保留规则结果作为主判


当前 `/api/collect` 处理链已经扩展为：

1. Proxy 网关上报请求
2. IDS 规范化事件
3. 规则检测
4. 机器学习推理
5. 规则 + ML 融合
6. 事件入库
7. 自动封禁判断
