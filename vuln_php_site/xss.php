<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$name = $_GET["name"] ?? "";
$preview = $name !== "" ? "Hello " . $name : "";

ob_start();
?>
<section class="panel">
  <h2>XSS 演示</h2>
  <p>该页面直接把 <code>name</code> 参数输出到页面中，不做任何 HTML 转义，可用于演示反射型 XSS。</p>
  <form method="get">
    <label>
      名称
      <input type="text" name="name" value="<?= demo_h($name) ?>" placeholder="<script>alert(1)</script>">
    </label>
    <div class="button-row">
      <button type="submit">渲染页面</button>
      <a class="back-link" href="xss.php">重置</a>
    </div>
  </form>
</section>

<section class="panel">
  <h2>快速测试</h2>
  <?= demo_examples([
      "script 标签" => "xss.php?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
      "事件型 XSS" => "xss.php?name=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E",
      "javascript 协议" => "xss.php?name=javascript%3Aalert%281%29",
      "SVG onload" => "xss.php?name=%3Csvg+onload%3Dalert%281%29%3E",
  ]) ?>
</section>

<?php if ($preview !== ""): ?>
<section class="panel">
  <h2>危险输出结果</h2>
  <div class="notice">下面内容未经过滤，浏览器会直接解析：</div>
  <div style="margin-top:12px"><?= $preview ?></div>
</section>
<?php endif; ?>
<?php
$content = ob_get_clean();
demo_render_page("XSS 演示", "用于测试 script、事件属性、javascript 协议等 XSS 特征。", $content);
