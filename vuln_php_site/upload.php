<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$message = "";
$savedPath = "";
$uploadDir = __DIR__ . "/uploads";

if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

if (isset($_FILES["file"]) && is_uploaded_file($_FILES["file"]["tmp_name"])) {
    $requestedName = $_GET["filename"] ?? "";
    $filename = $requestedName !== "" ? basename($requestedName) : basename($_FILES["file"]["name"]);
    $target = $uploadDir . "/" . $filename;
    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target)) {
        $savedPath = "uploads/" . $filename;
        $message = "上传成功，文件已保存到 " . $savedPath;
    } else {
        $message = "上传失败";
    }
}

ob_start();
?>
<section class="panel">
  <h2>文件上传 / WebShell 演示</h2>
  <p>该页面允许任意文件上传，并支持通过 <code>filename</code> 参数指定保存文件名。提交时会把危险文件名同步到查询串中，便于 IDS 识别上传类攻击。</p>
  <form method="post" enctype="multipart/form-data" id="upload-form" action="upload.php">
    <label>
      保存文件名（可选）
      <input type="text" id="filename-field" name="filename_hint" value="<?= demo_h($_GET["filename"] ?? "") ?>" placeholder="shell.php 或 avatar.jpg.php">
    </label>
    <label>
      选择文件
      <input type="file" name="file" id="file-field">
    </label>
    <div class="button-row">
      <button type="submit">上传文件</button>
      <a class="back-link" href="upload.php">重置</a>
    </div>
  </form>
</section>

<section class="panel">
  <h2>推荐测试</h2>
  <p class="muted">建议配合文件名 <code>shell.php</code>、<code>avatar.jpg.php</code>、<code>backup.phtml</code> 使用。</p>
  <?= demo_examples([
      "直接访问上传目录" => "uploads/",
      "访问上传后的脚本" => "uploads/shell.php?cmd=whoami",
  ]) ?>
</section>

<?php if ($message !== ""): ?>
<section class="panel">
  <h2>上传结果</h2>
  <div class="success"><?= demo_h($message) ?></div>
  <?php if ($savedPath !== ""): ?>
    <p><a class="example-link" href="<?= demo_h($savedPath) ?>">打开已上传文件</a></p>
  <?php endif; ?>
</section>
<?php endif; ?>

<script>
  document.getElementById("upload-form").addEventListener("submit", function () {
    const fileInput = document.getElementById("file-field");
    const nameField = document.getElementById("filename-field");
    const params = new URLSearchParams(window.location.search);
    let filename = nameField.value.trim();
    if (!filename && fileInput.files.length > 0) {
      filename = fileInput.files[0].name;
    }
    if (filename) {
      params.set("filename", filename);
    }
    this.action = "upload.php?" + params.toString();
  });
</script>
<?php
$content = ob_get_clean();
demo_render_page("文件上传演示", "用于演示危险脚本扩展名、双扩展和上传后访问。", $content);
