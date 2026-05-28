<?php

declare(strict_types=1);

require_once __DIR__ . "/bootstrap.php";

function unsafe_template_render(string $template): string
{
    $callback = static function (array $matches): string {
        $expression = trim($matches[1] !== "" ? $matches[1] : $matches[2]);
        try {
            $result = eval("return " . $expression . ";");
            if (is_scalar($result) || $result === null) {
                return (string) $result;
            }
            return json_encode($result, JSON_UNESCAPED_UNICODE) ?: "[non-scalar]";
        } catch (Throwable $e) {
            return "[template-error: " . $e->getMessage() . "]";
        }
    };

    return preg_replace_callback('/\{\{\s*(.*?)\s*\}\}|\$\{\s*(.*?)\s*\}/s', $callback, $template) ?? $template;
}

$template = $_GET["template"] ?? ($_GET["tpl"] ?? "");
$output = "";

if ($template !== "") {
    $output = unsafe_template_render($template);
}

ob_start();
?>
<section class="panel">
  <h2>模板表达式注入演示</h2>
  <p>该页面模拟一个危险的自定义模板渲染器，会把 <code>{{ ... }}</code> 或 <code>${ ... }</code> 里的表达式直接交给 <code>eval()</code> 处理。</p>
  <form method="get">
    <label>
      模板内容
      <textarea name="template" placeholder="{{7*7}} 或 ${7*7}"><?= demo_h($template) ?></textarea>
    </label>
    <div class="button-row">
      <button type="submit">渲染模板</button>
      <a class="back-link" href="ssti.php">重置</a>
    </div>
  </form>
</section>

<section class="panel">
  <h2>快速测试</h2>
  <?= demo_examples([
      "Jinja 风格" => "ssti.php?template=%7B%7B7*7%7D%7D",
      "EL 风格" => "ssti.php?template=%24%7B7*7%7D",
      "读取全局类" => "ssti.php?template=%7B%7B__CLASS__%7D%7D",
      "高危模板特征" => "ssti.php?template=%7B%7Bconfig.items%28%29%7D%7D",
  ]) ?>
</section>

<?php if ($template !== ""): ?>
<section class="panel">
  <h2>渲染结果</h2>
  <pre><?= demo_h($output) ?></pre>
</section>
<?php endif; ?>
<?php
$content = ob_get_clean();
demo_render_page("SSTI / 模板注入演示", "用于模拟服务端模板表达式被直接执行的危险场景。", $content);
