<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$xml = $_POST["xml"] ?? ($_GET["xml"] ?? "");
$result = "";

if ($xml !== "") {
    $dom = new DOMDocument();
    libxml_use_internal_errors(true);
    $ok = @$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_NONET);
    if ($ok) {
        $result = $dom->saveXML() ?: "XML 解析成功，但没有可输出内容。";
    } else {
        $errors = libxml_get_errors();
        $messages = [];
        foreach ($errors as $error) {
            $messages[] = trim($error->message);
        }
        libxml_clear_errors();
        $result = "XML 解析失败：\n" . implode("\n", $messages);
    }
}

ob_start();
?>
<section class="panel">
  <h2>XXE / XML 外部实体演示</h2>
  <p>该页面会用 <code>LIBXML_NOENT | LIBXML_DTDLOAD</code> 解析用户提交的 XML，并在提交前把 XML 内容同步到 URL 查询串中，便于 IDS 直接看到 <code>DOCTYPE</code>、<code>ENTITY</code> 等特征。</p>
  <form method="post" id="xxe-form" action="xxe.php">
    <label>
      XML 内容
      <textarea name="xml" id="xml-field" placeholder='<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'><?= demo_h($xml) ?></textarea>
    </label>
    <div class="button-row">
      <button type="submit">解析 XML</button>
      <a class="back-link" href="xxe.php">重置</a>
    </div>
  </form>
</section>

<section class="panel">
  <h2>快速测试</h2>
  <?= demo_examples([
      "读取 /etc/passwd" => "xxe.php?xml=%3C!DOCTYPE%20foo%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file:///etc/passwd%22%3E%5D%3E%3Cfoo%3E%26xxe%3B%3C/foo%3E",
      "PUBLIC 外部实体" => "xxe.php?xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20sp%20PUBLIC%20%22a%22%20%22file:///etc/passwd%22%3E%5D%3E%3Cr%3E%26sp%3B%3C/r%3E",
  ]) ?>
</section>

<?php if ($xml !== ""): ?>
<section class="panel">
  <h2>解析结果</h2>
  <pre><?= demo_h($result) ?></pre>
</section>
<?php endif; ?>

<script>
  document.getElementById("xxe-form").addEventListener("submit", function () {
    const xmlValue = document.getElementById("xml-field").value;
    const params = new URLSearchParams(window.location.search);
    params.set("xml", xmlValue);
    this.action = "xxe.php?" + params.toString();
  });
</script>
<?php
$content = ob_get_clean();
demo_render_page("XXE 演示", "用于测试 XML 外部实体注入和危险 DTD 解析。", $content);
