<?php
/**
 * 环境 / 部署检查
 * run_checks() 不依赖数据库，安装前后均可调用。
 * 返回: ['pass'=>bool, 'items'=>[ ['name','status','detail'], ... ]]
 */

function run_checks(): array {
    $items = [];
    $add = function (string $name, string $status, string $detail = '') use (&$items) {
        $items[] = ['name' => $name, 'status' => $status, 'detail' => $detail];
    };

    $installed = is_file(CONFIG_PATH) && is_file(DB_PATH);

    // 1. PHP 版本
    if (version_compare(PHP_VERSION, '7.4.0', '>=')) {
        $add('PHP 版本 ≥ 7.4', 'ok', '当前版本 ' . PHP_VERSION);
    } else {
        $add('PHP 版本 ≥ 7.4', 'fail', '当前版本 ' . PHP_VERSION . '，请升级 PHP。');
    }

    // 2. sqlite3 扩展（硬要求）
    if (class_exists('SQLite3')) {
        $v = method_exists('SQLite3', 'version') ? SQLite3::version() : ['versionString' => 'unknown'];
        $add('SQLite3 扩展（ext-sqlite3）', 'ok', '已启用，SQLite 版本 ' . ($v['versionString'] ?? 'unknown'));
    } else {
        $add('SQLite3 扩展（ext-sqlite3）', 'fail',
            '未启用。Ubuntu/Debian 安装：apt install php-sqlite3；宝塔在 PHP 设置中安装 sqlite3 扩展，然后重启 Web 服务。');
    }

    // 3. 必要函数
    $needFns = ['random_bytes', 'session_start', 'hash_equals', 'password_hash'];
    $missing = array_filter($needFns, fn($f) => !function_exists($f));
    $add('关键内置函数', $missing ? 'fail' : 'ok',
        $missing ? '缺少：' . implode(', ', $missing) : 'random_bytes / session / hash_equals / password_hash 均可用');

    // 3.5 mbstring（建议，用于中文备注/文件名处理；无则降级 substr）
    $add('mbstring 扩展（建议）', extension_loaded('mbstring') ? 'ok' : 'warn',
        extension_loaded('mbstring') ? '已启用。'
        : '未启用，中文字符串处理将降级为字节截断。建议安装：apt install php-mbstring');

    // 4. data 目录
    if (!is_dir(DATA_DIR)) {
        $add('data 目录存在', 'fail', '目录不存在：' . DATA_DIR);
    } elseif (!is_writable(DATA_DIR)) {
        $add('data 目录可写', 'fail',
            DATA_DIR . ' 不可写。请执行：chmod 750 data && chown www-data:www-data data（按实际运行用户调整）');
    } else {
        $add('data 目录可写', 'ok', DATA_DIR . '（权限 ' . substr(sprintf('%o', fileperms(DATA_DIR)), -4) . '）');
    }

    // 5. 数据库文件权限（已安装时检查 app.db 本身）
    if ($installed) {
        if (is_writable(DB_PATH)) {
            $add('数据库文件 app.db 可写', 'ok',
                DB_PATH . '（权限 ' . substr(sprintf('%o', fileperms(DB_PATH)), -4) . '）');
        } else {
            $add('数据库文件 app.db 可写', 'fail',
                DB_PATH . ' 不可写，请执行：chmod 640 data/app.db* && chown www-data:www-data data/app.db*');
        }
    }

    // 6. SQLite3 真实读写探针：在 data 目录建临时库做建表/写入/读取/删除
    if (is_dir(DATA_DIR) && is_writable(DATA_DIR) && class_exists('SQLite3')) {
        $probe = DATA_DIR . '/._probe_' . bin2hex(random_bytes(4)) . '.db';
        try {
            $s = new SQLite3($probe);
            $s->enableExceptions(true);
            $s->exec('CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)');
            $st = $s->prepare('INSERT INTO t(v) VALUES(:v)');
            $st->bindValue(':v', 'probe-' . now_fallback(), SQLITE3_TEXT);
            $st->execute();
            $r = $s->querySingle('SELECT v FROM t WHERE id=1');
            $s->exec('DELETE FROM t');
            $s->close();
            @unlink($probe);
            @unlink($probe . '-wal');
            @unlink($probe . '-shm');
            $add('SQLite3 读写权限探针', $r !== null && $r !== false ? 'ok' : 'fail',
                '已在 data 目录成功完成 建库→建表→写入→查询→删除 全流程。');
        } catch (Throwable $ex) {
            @unlink($probe);
            @unlink($probe . '-wal');
            @unlink($probe . '-shm');
            $add('SQLite3 读写权限探针', 'fail', '探针失败：' . $ex->getMessage());
        }
    } else {
        $add('SQLite3 读写权限探针', 'fail', '前置条件不满足（sqlite3 扩展或 data 写权限缺失），未执行。');
    }

    // 7. downloads 目录
    if (!is_dir(DOWNLOADS_DIR)) {
        $add('downloads 目录存在', 'warn', '目录不存在，后台上传安装包功能将不可用。');
    } elseif (!is_writable(DOWNLOADS_DIR)) {
        $add('downloads 目录可写', 'warn',
            '不可写，后台无法上传安装包（仍可用 FTP/SCP 手动放入文件）。建议：chmod 750 downloads && chown www-data:www-data downloads');
    } else {
        $add('downloads 目录可写', 'ok', DOWNLOADS_DIR);
    }

    // 8. 防直连保护
    $serverSoft = $_SERVER['SERVER_SOFTWARE'] ?? '';
    if (stripos($serverSoft, 'nginx') !== false) {
        $add('data 目录防下载（Nginx）', 'warn',
            '检测到 Nginx，.htaccess 不生效。请在站点配置中加入：<br>' .
            '<code>location ~* /(data)/ { deny all; }</code><br>' .
            'downloads 目录由 PHP 鉴权后输出，建议同样禁止直连：<code>location ^~ /downloads/ { deny all; }</code>');
    } else {
        if (is_file(DATA_DIR . '/.htaccess')) {
            $add('data 目录防下载（Apache）', 'ok', '.htaccess 已就位。');
        } else {
            $add('data 目录防下载（Apache）', 'warn', 'data/.htaccess 缺失，数据库可能被直接下载！');
        }
    }

    // 9. 安装文件
    if (is_file(BASE_DIR . '/install.php')) {
        $add('install.php 安装脚本', $installed ? 'warn' : 'info',
            $installed ? '系统已安装，建议立即删除 install.php，避免被重复执行。' : '尚未安装，请先执行安装。');
    }

    // 10. 上传限制（信息项）
    $add('PHP 上传大小限制', 'info',
        'upload_max_filesize=' . ini_get('upload_max_filesize') .
        '，post_max_size=' . ini_get('post_max_size') .
        '，可在 php.ini / 面板配置中调大。');

    // 11. HTTPS
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') == 443);
    $add('HTTPS 加密传输', $https ? 'ok' : 'warn',
        $https ? '已启用 HTTPS。' : '当前为明文 HTTP，公网部署强烈建议配置 HTTPS（卡密与会话安全）。');

    $hardFail = false;
    foreach ($items as $it) {
        if ($it['status'] === 'fail') { $hardFail = true; break; }
    }
    return ['pass' => !$hardFail, 'items' => $items];
}

function now_fallback(): int { return time(); }

/** 独立运行（安装向导）时 core.php 可能未加载，自带转义 */
if (!function_exists('e')) {
    function e(?string $s): string {
        return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    }
}

function render_check_items(array $items): string {
    $icon = ['ok' => '✓', 'fail' => '✗', 'warn' => '!', 'info' => 'i'];
    $h = '<ul class="check-list">';
    foreach ($items as $it) {
        $h .= '<li class="check ' . e($it['status']) . '">';
        $h .= '<span class="mark">[' . ($icon[$it['status']] ?? '?') . ']</span>';
        $h .= '<div><div>' . e($it['name']) . '</div>';
        if ($it['detail'] !== '') $h .= '<div class="detail">' . $it['detail'] . '</div>';
        $h .= '</div></li>';
    }
    return $h . '</ul>';
}
