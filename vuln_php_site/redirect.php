<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$next = $_GET["next"] ?? ($_GET["redirect"] ?? "");
$go = $_GET["go"] ?? "";

if ($next !== "" && $go === "1") {
    header("Location: " . $next);
    exit;
}

ob_start();
?>
<section class="panel">
  <h2>开放重定向演示</h2>
  <p>该页面会把 <code>next</code> 参数直接拼到 <code>Location</code> 头里。为了方便演示，默认只展示跳转目标；当 <code>go=1</code> 时会真的执行跳转。</p>
  <form method="get">
    <label>
      跳转目标
      <input type="text" name="next" value="<?= demo_h($next) ?>" placeholder="http://example.com">
    </label>
    <input type="hidden" name="go" value="1">
    <div class="button-row">
      <button type="submit">执行跳转</button>
      <a class="back-link" href="redirect.php">重置</a>
    </div>
  </form>
</section>

<section class="panel">
  <h2>快速测试</h2>
  <?= demo_examples([
      "跳转到外站" => "redirect.php?next=http://example.com&go=1",
      "双斜杠跳转" => "redirect.php?next=//evil.example.com&go=1",
      "带 CRLF" => "redirect.php?next=http://example.com%250d%250aX-Test%3A1",
  ]) ?>
</section>

<?php if ($next !== ""): ?>
<section class="panel">
  <h2>当前跳转目标</h2>
  <pre><?= demo_h($next) ?></pre>
</section>
<?php endif; ?>
<?php
$content = ob_get_clean();
demo_render_page("开放重定向演示", "用于测试 next / redirect 等跳转参数。", $content);
