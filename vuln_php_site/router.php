<?php
define("IDS_ROUTER_MODE", true);
require __DIR__ . "/logger.php";

$method = $_SERVER["REQUEST_METHOD"] ?? "GET";
$uri = $_SERVER["REQUEST_URI"] ?? "/";
$path = parse_url($uri, PHP_URL_PATH) ?: "/";
$relativePath = ltrim($path, "/");
$requested = $relativePath === "" ? __DIR__ . "/index.php" : __DIR__ . "/" . $relativePath;

function ids_send_static_file($absolutePath, $method)
{
    if (function_exists("mime_content_type")) {
        $mime = mime_content_type($absolutePath);
    } else {
        $mime = "application/octet-stream";
    }
    header("Content-Type: " . $mime);
    header("Content-Length: " . filesize($absolutePath));
    if (strtoupper($method) !== "HEAD") {
        readfile($absolutePath);
    }
}

if (is_file($requested)) {
    ids_log_request(200);
    $extension = strtolower(pathinfo($requested, PATHINFO_EXTENSION));
    if ($extension === "php") {
        require $requested;
    } else {
        ids_send_static_file($requested, $method);
    }
    return true;
}

if ($path === "/" || $path === "") {
    ids_log_request(200);
    require __DIR__ . "/index.php";
    return true;
}

ids_log_request(404);
http_response_code(404);
header("Content-Type: text/plain; charset=utf-8");
echo "Not Found";
return true;
