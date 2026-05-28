<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$filter = $_GET["filter"] ?? "";
$username = $_GET["username"] ?? "";
$password = $_GET["password"] ?? "";
$result = "";

if ($filter !== "" || $username !== "" || $password !== "") {
    $result = "模拟 MongoDB 查询条件：\n";
    if ($filter !== "") {
        $decoded = json_decode($filter, true);
        if (is_array($decoded)) {
            $result .= json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        } else {
            $result .= $filter;
        }
    } else {
        $result .= json_encode([
            "username" => $username,
            "password" => $password,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    }
}

ob_start();
?>
<section class="panel">
  <h2>NoSQL 注入演示</h2>
  <p>该页面模拟将 <code>filter</code> JSON 或用户名、密码条件直接拼接进 MongoDB 查询的场景。适合测试 <code>$where</code>、<code>$ne</code>、<code>$regex</code> 等特征。</p>
  <form method="get">
    <label>
      filter JSON
      <textarea name="filter" placeholder='{"$where":"this.password.length>0"}'><?= demo_h($filter) ?></textarea>
    </label>
    <label>
      username
      <input type="text" name="username" value="<?= demo_h($username) ?>" placeholder='{"$ne":null}'>
    </label>
    <label>
      password
      <input type="text" name="password" value="<?= demo_h($password) ?>" placeholder='{"$regex":".*"}'>
    </label>
    <div class="button-row">
      <button type="submit">执行查询</button>
      <a class="back-link" href="nosqli.php">重置</a>
    </div>
  </form>
</section>

<section class="panel">
  <h2>快速测试</h2>
  <?= demo_examples([
      '$where 条件注入' => "nosqli.php?filter=%7B%22%24where%22%3A%22this.password.length%3E0%22%7D",
      '$ne 绕过' => "nosqli.php?username=%7B%22%24ne%22%3Anull%7D&password=%7B%22%24ne%22%3Anull%7D",
      '$regex 枚举' => "nosqli.php?filter=%7B%22name%22%3A%7B%22%24regex%22%3A%22.*%22%7D%7D",
  ]) ?>
</section>

<?php if ($result !== ""): ?>
<section class="panel">
  <h2>模拟查询</h2>
  <pre><?= demo_h($result) ?></pre>
</section>
<?php endif; ?>
<?php
$content = ob_get_clean();
demo_render_page("NoSQL 注入演示", "用于测试 MongoDB 风格的查询操作符注入。", $content);
