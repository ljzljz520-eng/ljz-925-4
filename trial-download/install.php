<?php
/**
 * 安装向导：上传后浏览器访问本文件即可。
 * 安装完成后请删除本文件！
 */
error_reporting(E_ALL & ~E_DEPRECATED);
define('BASE_DIR', __DIR__);
define('DATA_DIR', __DIR__ . '/data');
define('DB_PATH', DATA_DIR . '/app.db');
define('CONFIG_PATH', DATA_DIR . '/config.php');
define('DOWNLOADS_DIR', __DIR__ . '/downloads');

require __DIR__ . '/lib/checks.php';

$installed = is_file(CONFIG_PATH) && is_file(DB_PATH);
$errors = [];

// 校验安装表单 token
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (session_status() !== PHP_SESSION_ACTIVE) { session_start(); }
    if (!isset($_POST['csrf']) || !is_string($_POST['csrf'])
        || !hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'])) {
        $errors[] = '安装表单已过期，请返回刷新页面后重试。';
    }
}

// 已安装：只读展示自检结果，拒绝重复安装
if ($installed) {
    $result = run_checks();
    ?><!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>系统已安装</title><link rel="stylesheet" href="assets/style.css"></head>
    <body><div class="wrap narrow">
      <div class="card">
        <h2>系统已安装</h2>
        <div class="alert warn">检测到系统已完成安装，install.php 已锁定为只读自检模式，不会执行任何写入操作。
        <strong>为安全起见，请立即删除本文件（install.php）。</strong></div>
        <div class="alert <?= $result['pass'] ? 'ok' : 'err' ?>">
          <?= $result['pass'] ? '硬性检查全部通过。' : '存在未通过的硬性检查项，请修复。' ?></div>
        <?= render_check_items($result['items']) ?>
        <div class="actions">
          <a class="btn" href="index.php">前往首页</a>
          <a class="btn secondary" href="admin.php">管理后台</a>
        </div>
      </div>
    </div></body></html><?php
    exit;
}

/* 提交安装 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $result = run_checks();
    if (!$result['pass']) {
        $errors[] = '硬性环境检查未通过，无法安装，请先修复上面标 ✗ 的项目。';
    }
    $adminUser = trim($_POST['admin_user'] ?? '');
    $pass1 = $_POST['password'] ?? '';
    $pass2 = $_POST['password2'] ?? '';
    $siteName = trim($_POST['site_name'] ?? '') ?: '试用软件下载中心';
    $timezone = trim($_POST['timezone'] ?? 'Asia/Shanghai');
    if (!preg_match('/^[A-Za-z0-9_]{3,32}$/', $adminUser)) {
        $errors[] = '管理员用户名需为 3-32 位字母、数字或下划线。';
    }
    if (strlen($pass1) < 8) $errors[] = '管理员密码至少 8 位。';
    if ($pass1 !== $pass2) $errors[] = '两次输入的密码不一致。';
    if (!in_array($timezone, timezone_identifiers_list(), true) && @date_default_timezone_set($timezone) === false) {
        $timezone = 'UTC';
    }

    if (!$errors) {
        // 1) 目录
        foreach ([DATA_DIR, DOWNLOADS_DIR] as $d) {
            if (!is_dir($d)) @mkdir($d, 0750, true);
        }
        // 2) 防直连
        $denyAll = "# 禁止外部直接访问本目录\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n"
                 . "<IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n</IfModule>\n";
        @file_put_contents(DATA_DIR . '/.htaccess', $denyAll);
        @file_put_contents(DOWNLOADS_DIR . '/.htaccess', $denyAll);
        @chmod(DATA_DIR, 0750);
        @chmod(DOWNLOADS_DIR, 0750);

        // 3) 数据库
        if (class_exists('SQLite3')) {
            $db = new SQLite3(DB_PATH);
            $db->enableExceptions(true);
            $db->exec('PRAGMA journal_mode = WAL;');
            $db->exec('PRAGMA foreign_keys = ON;');
            $db->exec('CREATE TABLE IF NOT EXISTS cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                card_key TEXT NOT NULL UNIQUE,
                batch TEXT NOT NULL DEFAULT "",
                note TEXT NOT NULL DEFAULT "",
                banned INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL DEFAULT 0,
                use_count INTEGER NOT NULL DEFAULT 0,
                download_count INTEGER NOT NULL DEFAULT 0,
                last_used_at INTEGER,
                last_download_at INTEGER,
                last_ip TEXT NOT NULL DEFAULT "",
                created_at INTEGER NOT NULL
            )');
            $db->exec('CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                card_id INTEGER,
                card_key_snapshot TEXT,
                action TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT "",
                ip TEXT NOT NULL DEFAULT "",
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(card_id) REFERENCES cards(id) ON DELETE SET NULL
            )');
            $db->exec('CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ""
            )');
            $db->exec('CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL,
                ip TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )');
            $db->exec('CREATE INDEX IF NOT EXISTS idx_cards_status ON cards(banned, expires_at)');
            $db->exec('CREATE INDEX IF NOT EXISTS idx_cards_batch ON cards(batch)');
            $db->exec('CREATE INDEX IF NOT EXISTS idx_logs_card ON logs(card_id)');
            $db->exec('CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at)');
            $db->exec('CREATE INDEX IF NOT EXISTS idx_rate ON rate_limits(scope, ip, created_at)');

            $defaults = ['site_name' => $siteName, 'notice' => '', 'timezone' => $timezone];
            foreach ($defaults as $k => $v) {
                $stmt = $db->prepare('INSERT INTO settings(key,value) VALUES(:k,:v)
                                      ON CONFLICT(key) DO UPDATE SET value=excluded.value');
                $stmt->bindValue(':k', $k, SQLITE3_TEXT);
                $stmt->bindValue(':v', $v, SQLITE3_TEXT);
                $stmt->execute();
                $stmt->close();
            }
            $db->close();
            @chmod(DB_PATH, 0640);
            @chmod(DB_PATH . '-wal', 0640);
            @chmod(DB_PATH . '-shm', 0640);

            // 4) 管理员配置
            $cfg = "<?php\n// 本文件由安装程序生成，包含密码哈希，请勿泄露或提交到公开仓库\nreturn [\n"
                 . "    'admin_user' => " . var_export($adminUser, true) . ",\n"
                 . "    'admin_hash' => " . var_export(password_hash($pass1, PASSWORD_DEFAULT), true) . ",\n"
                 . "];\n";
            if (file_put_contents(CONFIG_PATH, $cfg) === false) {
                $errors[] = 'config.php 写入失败，请检查 data 目录权限。';
            } else {
                @chmod(CONFIG_PATH, 0640);
            }
        } else {
            $errors[] = 'SQLite3 扩展不可用，无法创建数据库。';
        }
    }

    if (!$errors) {
        ?><!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>安装完成</title><link rel="stylesheet" href="assets/style.css"></head>
        <body><div class="wrap narrow">
          <div class="card">
            <h2>✅ 安装完成</h2>
            <div class="alert ok">数据库与管理员账号已创建，可以开始使用。</div>
            <ul>
              <li>管理后台：<code>admin.php</code>（用户名 <?= htmlspecialchars($adminUser, ENT_QUOTES) ?>）</li>
              <li>用户入口：<code>index.php</code></li>
            </ul>
            <div class="alert err"><strong>安全收尾（必做）：</strong>
              <ul>
                <li>立即删除本文件 <code>install.php</code>；</li>
                <li>Nginx 用户请按 README 配置 data/ 与 downloads/ 的 deny 规则（.htaccess 对 Nginx 无效）；</li>
                <li>建议站点启用 HTTPS。</li>
              </ul>
            </div>
            <div class="actions">
              <a class="btn" href="admin.php">进入管理后台</a>
              <a class="btn secondary" href="index.php">用户下载入口</a>
            </div>
          </div>
        </div></body></html><?php
        exit;
    }
}

$result = run_checks();
if (session_status() !== PHP_SESSION_ACTIVE) { session_start(); }
if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(32)); }
?>
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>安装向导 - 卡密试用下载系统</title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body>
<div class="wrap narrow">
  <div class="card">
    <h2>卡密试用下载系统 · 安装向导</h2>
    <?php if ($errors): ?><div class="alert err"><ul>
      <?php foreach ($errors as $err): ?><li><?= htmlspecialchars($err, ENT_QUOTES) ?></li><?php endforeach; ?>
    </ul></div><?php endif; ?>

    <div class="alert <?= $result['pass'] ? 'ok' : 'err' ?>">
      第 1 步 · 环境检查：<?= $result['pass'] ? '硬性检查全部通过，可以安装。' : '存在未通过的硬性检查项（✗），请先修复。' ?>
    </div>
    <?= render_check_items($result['items']) ?>
  </div>

  <div class="card">
    <h2>第 2 步 · 创建管理员</h2>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf'], ENT_QUOTES) ?>">
      <label>站点名称</label>
      <input type="text" name="site_name" value="<?= htmlspecialchars($_POST['site_name'] ?? '试用软件下载中心', ENT_QUOTES) ?>">
      <label>管理员用户名</label>
      <input type="text" name="admin_user" value="<?= htmlspecialchars($_POST['admin_user'] ?? 'admin', ENT_QUOTES) ?>"
             pattern="[A-Za-z0-9_]{3,32}" required>
      <label>登录密码（至少 8 位）</label>
      <input type="password" name="password" required minlength="8" autocomplete="new-password">
      <label>确认密码</label>
      <input type="password" name="password2" required minlength="8" autocomplete="new-password">
      <label>时区</label>
      <input type="text" name="timezone" value="<?= htmlspecialchars($_POST['timezone'] ?? 'Asia/Shanghai', ENT_QUOTES) ?>">
      <div class="actions">
        <button class="btn" type="submit" <?= $result['pass'] ? '' : 'disabled' ?>>
          <?= $result['pass'] ? '开始安装' : '请先修复环境问题' ?>
        </button>
      </div>
    </form>
  </div>
</div>
</body>
</html>
