<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$adminUrl = demo_base_url() . "/admin.php";
$proxyExamples = [
    "访问本机 admin" => demo_query_link("proxy.php", ["url" => $adminUrl]),
    "访问云元数据" => "proxy.php?url=http://169.254.169.254/latest/meta-data/",
    "dict 协议" => "proxy.php?url=dict://127.0.0.1:6379/dbsize",
    "file 协议读取 .env" => demo_query_link("proxy.php", ["url" => demo_file_uri(".env")]),
];

$url = $_GET["url"] ?? ($_GET["target"] ?? "");
$result = "";

if ($url !== "") {
    $context = stream_context_create([
        "http" => [
            "timeout" => 2,
        ],
    ]);
    $data = @file_get_contents($url, false, $context);
    if ($data === false) {
        $result = "代理请求失败或目标不可访问：\n" . $url;
    } else {
        $result = substr($data, 0, 1200);
    }
}

ob_start();
?>
<section class="panel">
  <h2>SSRF 代理演示</h2>
  <p>该页面直接把用户提供的 URL 用 <code>file_get_contents()</code> 取回，可用于演示内网探测、云元数据访问和危险协议访问。</p>
  <form method="get">
    <label>
      目标 URL
      <input type="text" name="url" value="<?= demo_h($url) ?>" placeholder="<?= demo_h($adminUrl) ?> 或 dict://127.0.0.1:6379/dbsize">
    </label>
    <div class="button-row">
      <button type="submit">发起请求</button>
      <a class="back-link" href="proxy.php">重置</a>
    </div>
  </form>
</section>

<section class="panel">
  <h2>快速测试</h2>
  <?= demo_examples($proxyExamples) ?>
</section>

<?php if ($url !== ""): ?>
<section class="panel">
  <h2>代理返回</h2>
  <pre><?= demo_h($result) ?></pre>
</section>
<?php endif; ?>
<?php
$content = ob_get_clean();
demo_render_page("SSRF 演示", "用于模拟服务器端请求伪造（SSRF）场景。", $content);
