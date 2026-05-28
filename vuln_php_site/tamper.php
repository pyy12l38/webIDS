<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

$fields = [
    "uid" => $_REQUEST["uid"] ?? "",
    "role" => $_REQUEST["role"] ?? "",
    "is_admin" => $_REQUEST["is_admin"] ?? "",
    "price" => $_REQUEST["price"] ?? "",
    "amount" => $_REQUEST["amount"] ?? "",
    "discount" => $_REQUEST["discount"] ?? "",
    "quantity" => $_REQUEST["quantity"] ?? "",
    "balance" => $_REQUEST["balance"] ?? "",
    "status" => $_REQUEST["status"] ?? "",
];

$payload = [];
foreach ($fields as $key => $value) {
    if ((string) $value !== "") {
        $payload[$key] = (string) $value;
    }
}

$result = $payload !== [] ? json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) : "";

ob_start();
?>
<section class="panel">
  <h2>参数篡改 / 业务参数攻击演示</h2>
  <p>该页面模拟订单确认和权限同步接口，会直接接收 <code>uid</code>、<code>role</code>、<code>is_admin</code>、<code>price</code>、<code>amount</code>、<code>discount</code>、<code>quantity</code>、<code>balance</code>、<code>status</code> 等关键参数，可用于演示业务参数篡改。</p>
  <form method="get">
    <label>
      用户 ID
      <input type="text" name="uid" value="<?= demo_h((string) $fields["uid"]) ?>" placeholder="1001">
    </label>
    <label>
      角色
      <input type="text" name="role" value="<?= demo_h((string) $fields["role"]) ?>" placeholder="user 或 admin">
    </label>
    <label>
      管理员标记
      <input type="text" name="is_admin" value="<?= demo_h((string) $fields["is_admin"]) ?>" placeholder="0 或 1">
    </label>
    <label>
      单价
      <input type="text" name="price" value="<?= demo_h((string) $fields["price"]) ?>" placeholder="199.00">
    </label>
    <label>
      金额
      <input type="text" name="amount" value="<?= demo_h((string) $fields["amount"]) ?>" placeholder="398.00">
    </label>
    <label>
      折扣
      <input type="text" name="discount" value="<?= demo_h((string) $fields["discount"]) ?>" placeholder="0">
    </label>
    <label>
      数量
      <input type="text" name="quantity" value="<?= demo_h((string) $fields["quantity"]) ?>" placeholder="2">
    </label>
    <label>
      余额
      <input type="text" name="balance" value="<?= demo_h((string) $fields["balance"]) ?>" placeholder="300.00">
    </label>
    <label>
      状态
      <input type="text" name="status" value="<?= demo_h((string) $fields["status"]) ?>" placeholder="pending / vip / paid">
    </label>
    <div class="button-row">
      <button type="submit">提交参数</button>
      <a class="back-link" href="tamper.php">重置</a>
    </div>
  </form>
</section>

<section class="panel">
  <h2>快速测试</h2>
  <?= demo_examples([
      "价格篡改" => "tamper.php?uid=1001&price=0.01&amount=0.01&quantity=99",
      "权限提权" => "tamper.php?uid=1001&role=admin&is_admin=1&status=vip",
      "余额覆盖" => "tamper.php?uid=1001&balance=999999&discount=100&status=paid",
      "复合参数篡改" => "tamper.php?uid=1001&role=admin&is_admin=1&price=0.01&amount=0.01&discount=100&quantity=50",
  ]) ?>
</section>

<?php if ($result !== ""): ?>
<section class="panel">
  <h2>接收到的业务参数</h2>
  <pre><?= demo_h($result) ?></pre>
</section>
<?php endif; ?>
<?php
$content = ob_get_clean();
demo_render_page("参数篡改演示", "用于测试 Web IDS 的业务参数篡改规则。", $content);
