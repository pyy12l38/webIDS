<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$profiles = [
    "sensitive" => [
        ["label" => "GET /.env", "url" => ".env", "method" => "GET"],
        ["label" => "GET /phpmyadmin", "url" => "phpmyadmin", "method" => "GET"],
        ["label" => "GET /swagger", "url" => "swagger", "method" => "GET"],
        ["label" => "GET /api-docs", "url" => "api-docs", "method" => "GET"],
    ],
    "scanner" => [
        ["label" => "HEAD /swagger", "url" => "swagger", "method" => "HEAD"],
        ["label" => "OPTIONS /api-docs", "url" => "api-docs", "method" => "OPTIONS"],
        ["label" => "GET /vendor/phpunit/eval-stdin.php", "url" => "vendor/phpunit/eval-stdin.php", "method" => "GET"],
        ["label" => "GET /manager/html", "url" => "manager/html", "method" => "GET"],
    ],
    "bruteforce" => [
        [
            "label" => "POST admin/wrongpass1",
            "url" => "login.php?login=admin&pwd=wrongpass1",
            "method" => "POST",
            "headers" => ["Content-Type" => "application/x-www-form-urlencoded"],
            "body" => "login=admin&pwd=wrongpass1",
        ],
        [
            "label" => "POST admin/wrongpass2",
            "url" => "login.php?login=admin&pwd=wrongpass2",
            "method" => "POST",
            "headers" => ["Content-Type" => "application/x-www-form-urlencoded"],
            "body" => "login=admin&pwd=wrongpass2",
        ],
        [
            "label" => "POST admin/wrongpass3",
            "url" => "login.php?login=admin&pwd=wrongpass3",
            "method" => "POST",
            "headers" => ["Content-Type" => "application/x-www-form-urlencoded"],
            "body" => "login=admin&pwd=wrongpass3",
        ],
        [
            "label" => "POST admin/wrongpass4",
            "url" => "login.php?login=admin&pwd=wrongpass4",
            "method" => "POST",
            "headers" => ["Content-Type" => "application/x-www-form-urlencoded"],
            "body" => "login=admin&pwd=wrongpass4",
        ],
    ],
    "combo" => [
        ["label" => "SQLi", "url" => "sqli.php?id=1+UNION+SELECT+load_file%28%27%2Fetc%2Fpasswd%27%29%2Cnull%2Cnull--", "method" => "GET"],
        ["label" => "LFI", "url" => "lfi.php?file=../../../../etc/passwd", "method" => "GET"],
        ["label" => "SSRF", "url" => demo_query_link("proxy.php", ["url" => demo_file_uri(".env")]), "method" => "GET"],
        ["label" => "RCE", "url" => "shell.php?cmd=whoami", "method" => "GET"],
    ],
];

ob_start();
?>
<section class="panel">
  <h2>批量流量生成器</h2>
  <p>点击下面按钮后，页面会连续发起多次请求，用来更稳定地触发当前 IDS 的敏感路径聚合、扫描探测、暴力破解与复合攻击链判断。</p>
  <div class="examples">
    <button type="button" class="secondary" data-profile="sensitive">触发敏感路径探测</button>
    <button type="button" class="secondary" data-profile="scanner">触发扫描方法</button>
    <button type="button" class="secondary" data-profile="bruteforce">触发暴力破解</button>
    <button type="button" class="secondary" data-profile="combo">触发组合攻击链</button>
  </div>
</section>

<section class="panel">
  <h2>手工入口</h2>
  <?= demo_examples([
      "手工打开 /.env" => ".env",
      "手工打开 /phpmyadmin" => "phpmyadmin",
      "手工打开 login.php" => "login.php",
      "手工打开 tamper.php" => "tamper.php",
  ]) ?>
</section>

<section class="panel">
  <h2>执行结果</h2>
  <pre id="runner-output">点击上方按钮后，这里会显示每一步请求的返回状态。</pre>
</section>

<script>
const profiles = <?= json_encode($profiles, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;
const output = document.getElementById("runner-output");

async function runProfile(name) {
  const steps = profiles[name] || [];
  const tracePrefix = `${Date.now()}_${name}`;
  const lines = [`开始执行 ${name}，共 ${steps.length} 个请求...`];
  output.textContent = lines.join("\n");

  for (let index = 0; index < steps.length; index += 1) {
    const step = steps[index];
    const separator = step.url.includes("?") ? "&" : "?";
    const trace = `${tracePrefix}_${index + 1}`;
    const finalUrl = `${step.url}${separator}trace=${encodeURIComponent(trace)}`;
    const options = {
      method: step.method || "GET",
      credentials: "same-origin",
      headers: step.headers || {},
    };
    if (step.body) {
      options.body = `${step.body}&trace=${encodeURIComponent(trace)}`;
    }

    try {
      const response = await fetch(finalUrl, options);
      lines.push(`[${index + 1}/${steps.length}] ${step.label} -> HTTP ${response.status}`);
    } catch (error) {
      lines.push(`[${index + 1}/${steps.length}] ${step.label} -> ERROR: ${error}`);
    }

    output.textContent = lines.join("\n");
    await new Promise((resolve) => setTimeout(resolve, 220));
  }

  output.textContent = lines.join("\n") + "\n\n已完成，请回到 IDS 页面查看最新告警。";
}

document.querySelectorAll("[data-profile]").forEach((button) => {
  button.addEventListener("click", () => runProfile(button.getAttribute("data-profile")));
});
</script>
<?php
$content = ob_get_clean();
demo_render_page("批量流量生成器", "用于一键生成聚合型攻击流量，便于验证当前 IDS 的行为级规则。", $content);
