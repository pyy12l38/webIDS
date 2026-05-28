<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$login = $_POST["login"] ?? ($_GET["login"] ?? "");
$pwd = $_POST["pwd"] ?? ($_GET["pwd"] ?? "");
$submitted = $_SERVER["REQUEST_METHOD"] === "POST";
$message = "";

if ($submitted) {
    $message = "登录失败：用户 " . $login . " 的密码验证未通过。";
}

ob_start();
?>
<section class="panel">
  <h2>弱认证 / 暴力破解演示</h2>
  <p>该页面模拟登录接口。为了让日志记录器拿到认证参数，提交时会把表单里的 <code>login</code> 和 <code>pwd</code> 同步到 URL 查询串中，再以 <code>POST</code> 方式提交。</p>
  <form method="post" id="login-form" action="login.php">
    <label>
      用户名
      <input type="text" name="login" id="login-field" value="<?= demo_h($login) ?>" placeholder="admin">
    </label>
    <label>
      密码
      <input type="text" name="pwd" id="pwd-field" value="<?= demo_h($pwd) ?>" placeholder="admin123">
    </label>
    <div class="button-row">
      <button type="submit">提交登录</button>
      <a class="back-link" href="login.php">重置</a>
    </div>
  </form>
</section>

<section class="panel">
  <h2>推荐测试</h2>
  <?= demo_examples([
      "POST 登录 admin / admin123" => "login.php?login=admin&pwd=admin123",
      "POST 登录 test / wrongpass" => "login.php?login=test&pwd=wrongpass",
      "配合扫描器 UA 访问" => "login.php?login=admin&pwd=wrongpass&tool=sqlmap",
  ]) ?>
</section>

<?php if ($submitted): ?>
<section class="panel">
  <h2>登录结果</h2>
  <div class="notice"><?= demo_h($message) ?></div>
</section>
<?php endif; ?>

<script>
  document.getElementById("login-form").addEventListener("submit", function () {
    const loginValue = document.getElementById("login-field").value;
    const pwdValue = document.getElementById("pwd-field").value;
    const params = new URLSearchParams(window.location.search);
    params.set("login", loginValue);
    params.set("pwd", pwdValue);
    this.action = "login.php?" + params.toString();
  });
</script>
<?php
$content = ob_get_clean();
demo_render_page("Login 暴力破解演示", "用于模拟匿名用户重复提交认证请求的场景。", $content);
