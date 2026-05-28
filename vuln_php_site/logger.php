<?php
// vuln_php_site/logger.php
// 本地开发模式的请求日志记录器。
// 在 Nginx + PHP-FPM 部署时，建议直接使用 Nginx access.log 作为 IDS 输入。

date_default_timezone_set("Asia/Shanghai");

function ids_log_request($statusOverride = null)
{
    if (defined("IDS_REQUEST_LOGGED")) {
        return;
    }
    define("IDS_REQUEST_LOGGED", true);

    $logDir = __DIR__ . "/logs";
    if (!is_dir($logDir)) {
        mkdir($logDir, 0777, true);
    }

    $logFile = $logDir . "/access.log";
    $blocklistFile = __DIR__ . "/../ids_site/blocked_ips.json";

    $ts = date("Y-m-d H:i:s");
    $ip = $_SERVER["REMOTE_ADDR"] ?? "-";
    $method = $_SERVER["REQUEST_METHOD"] ?? "-";
    $uri = $_SERVER["REQUEST_URI"] ?? "-";

    $parts = explode("?", $uri, 2);
    $path = $parts[0];
    $query = $parts[1] ?? "";

    $bodyQuery = "";
    if (in_array($method, ["POST", "PUT", "PATCH", "DELETE"], true)) {
        $rawBody = file_get_contents("php://input");
        if (is_string($rawBody) && $rawBody !== "" && strlen($rawBody) <= 8192) {
            $bodyQuery = $rawBody;
        } elseif (!empty($_POST)) {
            $bodyQuery = http_build_query($_POST);
        }
    }
    if ($bodyQuery !== "") {
        $bodyQuery = str_replace(["\t", "\r", "\n"], " ", $bodyQuery);
        $query = $query !== "" ? $query . "&" . $bodyQuery : $bodyQuery;
    }

    $status = (string) ($statusOverride ?? "200");
    $user = "-";
    $ua = $_SERVER["HTTP_USER_AGENT"] ?? "-";

    $isBlocked = false;
    if (file_exists($blocklistFile)) {
        $rawBlocklist = file_get_contents($blocklistFile);
        $decoded = json_decode($rawBlocklist, true);
        if (is_array($decoded) && array_key_exists($ip, $decoded)) {
            $isBlocked = true;
        }
    }

    if ($isBlocked) {
        $status = "403";
        $line = $ts . "\t" . $ip . "\t" . $method . "\t" . $path . "\t" . $query . "\t" . $status . "\t" . $user . "\t" . $ua . "\n";
        file_put_contents($logFile, $line, FILE_APPEND);
        http_response_code(403);
        header("Content-Type: text/plain; charset=utf-8");
        echo "该 IP 已被 IDS 封禁，禁止继续访问 PHP 漏洞站。";
        exit;
    }

    $line = $ts . "\t" . $ip . "\t" . $method . "\t" . $path . "\t" . $query . "\t" . $status . "\t" . $user . "\t" . $ua . "\n";
    file_put_contents($logFile, $line, FILE_APPEND);
}

if (!defined("IDS_ROUTER_MODE")) {
    ids_log_request();
}
?>
