<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$fileExamples = [
    "路径穿越读取 /etc/passwd" => "lfi.php?file=../../../../etc/passwd",
    "读取 Win.ini" => "lfi.php?file=..%5C..%5Cwindows%5Cwin.ini",
    "php://filter 读取 index.php" => "lfi.php?file=php://filter/convert.base64-encode/resource=index.php",
    "file:// 读取 .env" => demo_query_link("lfi.php", ["file" => demo_file_uri(".env")]),
];

$file = $_GET["file"] ?? ($_GET["page"] ?? "");
$output = "";

if ($file !== "") {
    $target = $file;
    $data = @file_get_contents($target);
    if ($data === false) {
        $output = "读取失败或文件不存在：" . $target;
    } else {
        $output = substr($data, 0, 4000);
    }
}

ob_start();
?>
<section class="panel">
  <h2>本地文件包含 / 任意文件读取</h2>
  <p>该页面将用户提交的 <code>file</code> / <code>page</code> 参数直接用于读取文件内容，可用于演示路径穿越、文件包装器和敏感文件访问。</p>
  <form method="get">
    <label>
      文件路径
      <input type="text" name="file" value="<?= demo_h($file) ?>" placeholder="../../../../etc/passwd 或 php://filter/convert.base64-encode/resource=index.php">
    </label>
    <div class="button-row">
      <button type="submit">读取文件</button>
      <a class="back-link" href="lfi.php">重置</a>
    </div>
  </form>
</section>

<section class="panel">
  <h2>快速测试</h2>
  <?= demo_examples($fileExamples) ?>
</section>

<?php if ($file !== ""): ?>
<section class="panel">
  <h2>读取结果</h2>
  <pre><?= demo_h($output) ?></pre>
</section>
<?php endif; ?>
<?php
$content = ob_get_clean();
demo_render_page("LFI / 文件读取演示", "用于演示路径穿越、文件包装器和敏感文件读取。", $content);
