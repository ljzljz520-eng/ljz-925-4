<?php
/**
 * 卡密试用下载系统 - 核心库
 * PHP >= 7.4，依赖 ext-sqlite3
 */

// ---------- 常量 ----------
define('APP_NAME', '试用软件下载中心');
define('BASE_DIR', dirname(__DIR__));
define('DATA_DIR', BASE_DIR . '/data');
define('DB_PATH', DATA_DIR . '/app.db');
define('CONFIG_PATH', DATA_DIR . '/config.php');
define('DOWNLOADS_DIR', BASE_DIR . '/downloads');

// 限流：同一 IP 验证失败 15 次后锁定 10 分钟
define('VERIFY_MAX_FAILS', 15);
define('VERIFY_LOCK_SECONDS', 600);
define('LOGIN_MAX_FAILS', 8);
define('LOGIN_LOCK_SECONDS', 600);

// ---------- 配置 ----------
function load_config(): array {
    if (!is_file(CONFIG_PATH)) {
        http_response_code(503);
        die('系统尚未安装，请先访问 <a href="install.php">install.php</a> 完成安装。');
    }
    return require CONFIG_PATH;
}

function cfg(string $key, $default = null) {
    static $config = null;
    if ($config === null) {
        $config = load_config();
    }
    return $config[$key] ?? $default;
}

// ---------- 数据库（SQLite3 扩展） ----------
function db(): SQLite3 {
    static $db = null;
    if ($db !== null) {
        return $db;
    }
    $db = new SQLite3(DB_PATH, SQLITE3_OPEN_READWRITE);
    $db->busyTimeout(5000);
    $db->enableExceptions(true);
    $db->exec('PRAGMA journal_mode = WAL;');
    $db->exec('PRAGMA foreign_keys = ON;');
    return $db;
}

/** 预处理查询并返回 SQLite3Result */
function db_query(string $sql, array $params = []): SQLite3Result {
    $stmt = db()->prepare($sql);
    foreach ($params as $k => $v) {
        $type = SQLITE3_TEXT;
        if (is_int($v)) $type = SQLITE3_INTEGER;
        elseif (is_float($v)) $type = SQLITE3_FLOAT;
        elseif (is_null($v)) $type = SQLITE3_NULL;
        $stmt->bindValue(is_int($k) ? $k + 1 : ':' . $k, $v, $type);
    }
    return $stmt->execute();
}

/** 取单行 */
function db_one(string $sql, array $params = []): ?array {
    $res = db_query($sql, $params);
    $row = $res->fetchArray(SQLITE3_ASSOC);
    return $row === false ? null : $row;
}

/** 取全部行 */
function db_all(string $sql, array $params = []): array {
    $res = db_query($sql, $params);
    $rows = [];
    while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
        $rows[] = $row;
    }
    return $rows;
}

/** 写入/更新，返回受影响行数；插入后的自增 ID 请用 db_insert_id() */
function db_exec(string $sql, array $params = []): int {
    db_query($sql, $params);
    return (int) db()->changes();
}

/** 插入并返回自增 ID */
function db_insert(string $sql, array $params = []): int {
    db_query($sql, $params);
    return (int) db()->lastInsertRowID();
}

// ---------- 设置表 ----------
function get_settings(): array {
    static $cache = null;
    if ($cache !== null) return $cache;
    $cache = [];
    foreach (db_all('SELECT key, value FROM settings') as $r) {
        $cache[$r['key']] = $r['value'];
    }
    return $cache;
}

function setting(string $key, string $default = ''): string {
    $s = get_settings();
    return $s[$key] ?? $default;
}

function set_setting(string $key, string $value): void {
    db_exec(
        'INSERT INTO settings(key, value) VALUES(:k,:v)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value',
        ['k' => $key, 'v' => $value]
    );
}

// ---------- 基础工具 ----------
function e(?string $s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

function base_url(): string {
    static $base = null;
    if ($base !== null) return $base;
    $dir = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
    $base = rtrim($dir === '/' ? '' : $dir, '/');
    return $base;
}

function url(string $path = ''): string {
    return base_url() . '/' . ltrim($path, '/');
}

function redirect(string $path): void {
    header('Location: ' . (strpos($path, '://') !== false ? $path : url($path)));
    exit;
}

function client_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function now(): int { return time(); }

function fmt_date(?int $ts): string {
    if (!$ts) return '-';
    return date('Y-m-d H:i', $ts);
}

function hsize(int $bytes): string {
    $u = ['B', 'KB', 'MB', 'GB'];
    $i = 0;
    $v = (float)$bytes;
    while ($v >= 1024 && $i < 3) { $v /= 1024; $i++; }
    return ($i === 0 ? $v : round($v, 1)) . ' ' . $u[$i];
}

// ---------- 会话 / CSRF ----------
function boot_session(): void {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => ini_get('session.cookie_path') ?: '/',
            'httponly' => true,
            'samesite' => 'Lax',
            'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        ]);
        session_name('TKDSESS');
        session_start();
    }
}

function csrf_token(): string {
    boot_session();
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_field(): string {
    return '<input type="hidden" name="csrf" value="' . e(csrf_token()) . '">';
}

function csrf_check(): void {
    boot_session();
    $t = $_POST['csrf'] ?? '';
    if (!is_string($t) || !hash_equals($_SESSION['csrf'] ?? '', $t)) {
        http_response_code(419);
        die('表单已过期或非法请求（CSRF 校验失败），请返回重试。');
    }
}

function flash(string $type, string $msg): void {
    boot_session();
    $_SESSION['flash'][] = ['type' => $type, 'msg' => $msg];
}

function take_flash(): array {
    boot_session();
    $f = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return $f;
}

// ---------- 卡密 ----------
function normalize_key(string $key): string {
    return strtoupper(preg_replace('/[^A-Za-z0-9]/', '', trim($key)));
}

function format_key(string $key): string {
    return implode('-', str_split($key, 4));
}

/** 生成随机卡密（去易混字符 0/O/1/I） */
function generate_key(int $len = 20): string {
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $max = strlen($alphabet) - 1;
    $out = '';
    for ($i = 0; $i < $len; $i++) {
        $out .= $alphabet[random_int(0, $max)];
    }
    return $out;
}

function card_expired(array $card): bool {
    return (int)$card['expires_at'] !== 0 && (int)$card['expires_at'] < now();
}

/** 当前状态：active / expired / banned */
function card_status(array $card): string {
    if ((int)$card['banned'] === 1) return 'banned';
    if (card_expired($card)) return 'expired';
    return 'active';
}

function status_label(string $s): string {
    return ['active' => '正常', 'expired' => '已过期', 'banned' => '已封禁'][$s] ?? $s;
}

function find_card_by_key(string $key): ?array {
    return db_one('SELECT * FROM cards WHERE card_key = :k', ['k' => $key]);
}

// ---------- 日志 / 限流 ----------
function add_log(?int $card_id, ?string $key_snapshot, string $action, string $detail = '', bool $admin = false): void {
    db_exec(
        'INSERT INTO logs(card_id, card_key_snapshot, action, detail, ip, is_admin, created_at)
         VALUES(:cid,:key,:act,:det,:ip,:adm,:t)',
        [
            'cid' => $card_id,
            'key' => $key_snapshot,
            'act' => $action,
            'det' => $detail,
            'ip' => client_ip(),
            'adm' => $admin ? 1 : 0,
            't' => now(),
        ]
    );
}

function action_label(string $a): string {
    $map = [
        'verify_ok'    => '验证成功',
        'verify_fail'  => '验证失败',
        'download'     => '下载文件',
        'ban'          => '封禁卡密',
        'unban'        => '解封卡密',
        'delete'       => '删除卡密',
        'generate'     => '批量生成',
        'login_ok'     => '管理员登录',
        'login_fail'   => '登录失败',
        'logout'       => '退出登录',
        'upload'       => '上传安装包',
        'delete_file'  => '删除安装包',
        'password'     => '修改密码',
        'settings'     => '修改设置',
    ];
    return $map[$a] ?? $a;
}

/**
 * 通用限流
 * @return bool true=允许, false=已锁定
 */
function rate_check(string $scope, int $max, int $window): bool {
    $since = now() - $window;
    $row = db_one(
        'SELECT COUNT(*) AS c FROM rate_limits WHERE scope=:s AND ip=:ip AND created_at>=:t',
        ['s' => $scope, 'ip' => client_ip(), 't' => $since]
    );
    return ((int)($row['c'] ?? 0)) < $max;
}

function rate_hit(string $scope): void {
    db_exec(
        'INSERT INTO rate_limits(scope, ip, created_at) VALUES(:s,:ip,:t)',
        ['s' => $scope, 'ip' => client_ip(), 't' => now()]
    );
}

function rate_clear(string $scope, ?string $ip = null): void {
    db_exec('DELETE FROM rate_limits WHERE scope=:s AND ip=:ip',
        ['s' => $scope, 'ip' => $ip ?? client_ip()]);
}

// ---------- 下载授权 ----------
function set_download_auth(int $cardId): void {
    boot_session();
    $_SESSION['dl_card_id'] = $cardId;
}

function authed_card(): ?array {
    boot_session();
    if (empty($_SESSION['dl_card_id'])) return null;
    $card = db_one('SELECT * FROM cards WHERE id=:id', ['id' => (int)$_SESSION['dl_card_id']]);
    if (!$card || card_status($card) !== 'active') return null;
    return $card;
}

function clear_download_auth(): void {
    boot_session();
    unset($_SESSION['dl_card_id']);
}

// ---------- 安装包 ----------
function package_files(): array {
    $files = [];
    foreach (glob(DOWNLOADS_DIR . '/*') ?: [] as $f) {
        if (is_file($f) && basename($f) !== '.htaccess') {
            $files[] = ['name' => basename($f), 'size' => (int)filesize($f), 'mtime' => (int)filemtime($f)];
        }
    }
    usort($files, fn($a, $b) => $b['mtime'] <=> $a['mtime']);
    return $files;
}

/** 安全校验文件名，防止路径穿越 */
function safe_filename(string $name): ?string {
    $name = basename(str_replace('\\', '/', $name));
    if ($name === '' || $name === '.' || $name === '..') return null;
    if (preg_match('/[\x00-\x1f]/', $name)) return null;
    if (!preg_match('/^[A-Za-z0-9._\-\x{4e00}-\x{9fa5}]+$/u', $name)) return null;
    return $name;
}

// ---------- 管理员 ----------
function is_admin(): bool {
    boot_session();
    return !empty($_SESSION['admin_id']);
}

function require_admin(): void {
    if (!is_admin()) redirect('admin.php');
}

/** 分页渲染，保留现有查询参数 */
function render_pagination(int $page, int $totalPages, array $query): string {
    if ($totalPages <= 1) return '';
    unset($query['page']);
    $make = fn($p) => http_build_query(array_merge($query, ['page' => $p]));
    $h = '<div class="pager">';
    $h .= $page > 1
        ? '<a href="?' . e($make($page - 1)) . '">上一页</a>'
        : '<span class="disabled">上一页</span>';
    $h .= '<span class="info">第 ' . $page . ' / ' . $totalPages . ' 页</span>';
    $h .= $page < $totalPages
        ? '<a href="?' . e($make($page + 1)) . '">下一页</a>'
        : '<span class="disabled">下一页</span>';
    return $h . '</div>';
}
