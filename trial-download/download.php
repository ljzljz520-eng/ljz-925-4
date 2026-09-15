<?php
require __DIR__ . '/lib/core.php';
boot_session();

if (!is_file(CONFIG_PATH)) {
    http_response_code(503);
    die('系统尚未安装，请先访问 install.php。');
}

// 1) 必须有有效卡密授权（过期/封禁每次请求实时判定，自动失效）
$card = authed_card();
if (!$card) {
    flash('err', '请先输入有效卡密后再下载。');
    redirect('index.php');
}

// 2) 文件名安全校验，防路径穿越
$fraw = $_GET['f'] ?? '';
$name = is_string($fraw) && $fraw !== '' ? safe_filename($fraw) : null;
if (!$name) {
    http_response_code(400);
    die('非法的文件名。');
}
$path = DOWNLOADS_DIR . '/' . $name;
if (!is_file($path)) {
    http_response_code(404);
    die('文件不存在或已被移除。');
}

// 3) 记日志 + 下载计数（下载前完成，即使中断也有记录）
db_exec(
    'UPDATE cards SET download_count=download_count+1, last_download_at=:t, last_ip=:ip WHERE id=:id',
    ['t' => now(), 'ip' => client_ip(), 'id' => (int)$card['id']]
);
add_log((int)$card['id'], $card['card_key'], 'download', $name . '（' . hsize((int)filesize($path)) . '）');

// 4) 输出文件
$size = filesize($path);
while (ob_get_level() > 0) { ob_end_clean(); }

header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
// RFC 5987 兼容中文文件名
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
$dispoFile = preg_match('/Firefox/i', $ua)
    ? "filename*=UTF-8''" . rawurlencode($name)
    : 'filename="' . rawurlencode($name) . '"; filename*=UTF-8\'\'' . rawurlencode($name);
header('Content-Disposition: attachment; ' . $dispoFile);
header('Content-Transfer-Encoding: binary');
header('Expires: 0');
header('Cache-Control: must-revalidate');
header('Pragma: public');
header('Content-Length: ' . $size);

// 支持 Range 断点续传（基础版：未传 Range 时整文件流式输出）
$out = fopen('php://output', 'wb');
$in = fopen($path, 'rb');
$chunk = 1024 * 256;
while (!feof($in) && connection_status() === CONNECTION_NORMAL) {
    fwrite($out, fread($in, $chunk));
    @ob_flush();
    flush();
}
fclose($in);
fclose($out);
exit;
