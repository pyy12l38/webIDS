<?php

declare(strict_types=1);

date_default_timezone_set("Asia/Shanghai");

require_once __DIR__ . "/common.php";

function demo_server_value(array $keys, string $default = ""): string
{
    foreach ($keys as $key) {
        $value = $_SERVER[$key] ?? "";
        if ($value !== "") {
            return trim((string) $value);
        }
    }
    return $default;
}

function demo_request_scheme(): string
{
    $forwarded = demo_server_value(["HTTP_X_FORWARDED_PROTO", "REQUEST_SCHEME"]);
    if ($forwarded !== "") {
        return strtolower(trim(explode(",", $forwarded)[0]));
    }

    $https = strtolower(demo_server_value(["HTTPS"]));
    return ($https !== "" && $https !== "off") ? "https" : "http";
}

function demo_request_host(): string
{
    $host = demo_server_value(["HTTP_X_FORWARDED_HOST", "HTTP_HOST", "SERVER_NAME"], "127.0.0.1:8080");
    return trim(explode(",", $host)[0]);
}

function demo_base_url(): string
{
    return demo_request_scheme() . "://" . demo_request_host();
}

function demo_site_path(string $relative = ""): string
{
    $relative = ltrim($relative, "/");
    $candidate = $relative === "" ? __DIR__ : __DIR__ . "/" . $relative;
    $real = realpath($candidate);
    return $real !== false ? $real : $candidate;
}

function demo_file_uri(string $relative): string
{
    return "file://" . demo_site_path($relative);
}

function demo_query_link(string $script, array $params = []): string
{
    if ($params === []) {
        return $script;
    }
    return $script . "?" . http_build_query($params, "", "&", PHP_QUERY_RFC3986);
}

function demo_client_ip(): string
{
    $forwarded = demo_server_value(["HTTP_X_FORWARDED_FOR"]);
    if ($forwarded !== "") {
        return trim(explode(",", $forwarded)[0]);
    }
    return demo_server_value(["HTTP_X_REAL_IP", "REMOTE_ADDR"], "-");
}

function demo_is_ip_blocked(): bool
{
    $blocklistFile = __DIR__ . "/../ids_site/blocked_ips.json";
    if (!is_file($blocklistFile)) {
        return false;
    }

    $decoded = json_decode((string) file_get_contents($blocklistFile), true);
    if (!is_array($decoded)) {
        return false;
    }

    return array_key_exists(demo_client_ip(), $decoded);
}

function demo_enforce_blocklist(): void
{
    if (!demo_is_ip_blocked()) {
        return;
    }

    http_response_code(403);
    $content = '
<section class="panel">
  <h2>访问已被阻断</h2>
  <div class="notice">当前来源 IP 已被 IDS 封禁，动态 PHP 页面访问已被阻止。</div>
  <p>如果你已经切换到 Nginx access.log 作为日志源，建议同步在 Nginx 层补充静态资源访问控制。</p>
</section>';
    demo_render_page("PHP 漏洞站访问被阻断", "该页面由 bootstrap.php 统一拦截返回。", $content);
    exit;
}

demo_enforce_blocklist();
