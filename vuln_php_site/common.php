<?php

declare(strict_types=1);

function demo_h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}

function demo_examples(array $examples): string
{
    $html = '<div class="examples">';
    foreach ($examples as $label => $url) {
        $html .= '<a class="example-link" href="' . demo_h($url) . '">' . demo_h($label) . '</a>';
    }
    $html .= "</div>";
    return $html;
}

function demo_render_page(string $title, string $description, string $content): void
{
    echo '<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>' . demo_h($title) . '</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f7fb;
      --card: #ffffff;
      --line: #d7deea;
      --text: #163047;
      --muted: #58708a;
      --primary: #2e68ff;
      --danger: #d9485f;
      --success: #218a5b;
      --code: #0d1b2a;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: linear-gradient(180deg, #f8fbff 0%, var(--bg) 100%);
      color: var(--text);
    }
    .page {
      max-width: 1080px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
      margin-bottom: 24px;
    }
    .header h1 {
      margin: 0 0 8px;
      font-size: 30px;
      line-height: 1.15;
    }
    .header p {
      margin: 0;
      color: var(--muted);
      line-height: 1.7;
    }
    .back-link {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 10px 14px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.88);
      color: var(--text);
      text-decoration: none;
      white-space: nowrap;
    }
    .panel {
      background: var(--card);
      border: 1px solid rgba(196, 207, 224, 0.85);
      border-radius: 20px;
      padding: 20px;
      margin-bottom: 18px;
      box-shadow: 0 12px 40px rgba(20, 48, 76, 0.08);
    }
    .panel h2 {
      margin: 0 0 12px;
      font-size: 19px;
    }
    .panel p {
      margin: 0 0 12px;
      color: var(--muted);
      line-height: 1.7;
    }
    form {
      display: grid;
      gap: 12px;
    }
    label {
      display: grid;
      gap: 8px;
      font-size: 14px;
      color: var(--muted);
    }
    input, textarea, select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px 14px;
      font-size: 14px;
      color: var(--text);
      background: #fff;
    }
    textarea {
      min-height: 140px;
      resize: vertical;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .button-row {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }
    button {
      border: 0;
      border-radius: 999px;
      background: var(--primary);
      color: #fff;
      padding: 12px 18px;
      font-size: 14px;
      cursor: pointer;
    }
    button.secondary {
      background: #e9eef8;
      color: var(--text);
    }
    .examples {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    .example-link {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      border: 1px solid #bfd0ff;
      background: #eef4ff;
      color: #1f52d1;
      text-decoration: none;
      padding: 10px 14px;
      font-size: 13px;
    }
    .code, pre {
      margin: 0;
      background: var(--code);
      color: #e7f0fb;
      border-radius: 16px;
      padding: 16px;
      overflow: auto;
      font-size: 13px;
      line-height: 1.6;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .notice {
      padding: 14px 16px;
      border-radius: 14px;
      border: 1px solid #ffd4da;
      background: #fff3f5;
      color: var(--danger);
      font-size: 14px;
      line-height: 1.7;
    }
    .success {
      padding: 14px 16px;
      border-radius: 14px;
      border: 1px solid #cdebdc;
      background: #eefaf3;
      color: var(--success);
      font-size: 14px;
      line-height: 1.7;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
    }
    .muted {
      color: var(--muted);
      font-size: 13px;
    }
  </style>
</head>
<body>
  <main class="page">
    <div class="header">
      <div>
        <h1>' . demo_h($title) . '</h1>
        <p>' . demo_h($description) . '</p>
      </div>
      <a class="back-link" href="index.php">返回漏洞导航</a>
    </div>
    ' . $content . '
  </main>
</body>
</html>';
}
