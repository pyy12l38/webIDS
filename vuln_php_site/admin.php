<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$content = '
<section class="panel">
  <h2>后台页面暴露演示</h2>
  <p>该页面模拟对外暴露的管理入口。访问 <code>/admin.php</code> 可以触发 IDS 对敏感路径的检测。</p>
  <div class="notice">这是一个未做认证保护的后台演示页，仅用于本地 IDS 测试。</div>
</section>

<section class="panel">
  <h2>推荐测试</h2>
  ' . demo_examples([
      "直接访问 /admin.php" => "admin.php",
      "带扫描器 UA 访问 /admin.php" => "admin.php?ua=scan",
      "访问 /.env" => ".env",
      "访问 /.git/config" => ".git/config",
  ]) . '
</section>';

demo_render_page("Admin 暴露演示", "用于演示敏感路径与后台入口暴露。", $content);
