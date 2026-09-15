<?php
require __DIR__ . '/lib/core.php';
require __DIR__ . '/lib/checks.php';

if (!is_file(CONFIG_PATH)) {
    http_response_code(503);
    echo '系统尚未安装，请先访问 <a href="install.php">install.php</a>。';
    exit;
}

boot_session();
date_default_timezone_set(setting('timezone', 'Asia/Shanghai'));

$adminUser = cfg('admin_user');
$adminHash = cfg('admin_hash');

/* ================= 未登录：登录页 / 登录处理 ================= */
if (!is_admin()) {
    $err = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
        csrf_check();
        $u = trim($_POST['username'] ?? '');
        $p = $_POST['password'] ?? '';

        if (!rate_check('login', LOGIN_MAX_FAILS, LOGIN_LOCK_SECONDS)) {
            $err = '失败次数过多，请 ' . round(LOGIN_LOCK_SECONDS / 60) . ' 分钟后再试。';
            add_log(null, null, 'login_fail', '账号[' . $u . ']触发锁定', true);
        } elseif (hash_equals($adminUser, $u) && password_verify($p, $adminHash)) {
            session_regenerate_id(true);
            $_SESSION['admin_id'] = 1;
            $_SESSION['admin_user'] = $u;
            rate_clear('login');
            add_log(null, null, 'login_ok', '管理员 ' . $u . ' 登录成功', true);
            redirect('admin.php');
        } else {
            rate_hit('login');
            $err = '用户名或密码错误。';
            add_log(null, null, 'login_fail', '账号[' . $u . ']登录失败', true);
        }
    }
    ?>
<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>管理登录 - <?= e(APP_NAME) ?></title>
<link rel="stylesheet" href="<?= e(url('assets/style.css')) ?>"></head>
<body><div class="wrap narrow">
  <div class="card">
    <h2>管理后台登录</h2>
    <?php if ($err): ?><div class="alert err"><?= e($err) ?></div><?php endif; ?>
    <form method="post">
      <?= csrf_field() ?>
      <input type="hidden" name="action" value="login">
      <label>用户名</label>
      <input type="text" name="username" required autofocus autocomplete="username">
      <label>密码</label>
      <input type="password" name="password" required autocomplete="current-password">
      <div class="actions"><button class="btn" type="submit">登录</button>
        <a class="btn secondary" href="<?= e(url('index.php')) ?>">返回首页</a></div>
    </form>
  </div>
</div></body></html>
    <?php
    exit;
}

/* ================= 已登录：POST 动作处理（PRG） ================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = $_POST['action'] ?? '';

    switch ($action) {
        case 'logout':
            add_log(null, null, 'logout', '管理员退出', true);
            $_SESSION = [];
            session_destroy();
            redirect('admin.php');

        case 'generate':
            $count = max(1, min(500, (int)($_POST['count'] ?? 10)));
            $days  = (int)($_POST['valid_days'] ?? 30); // -1=永久 0=当天
            $keyLen = max(12, min(32, (int)($_POST['key_len'] ?? 20)));
            $noteRaw = trim($_POST['note'] ?? '');
            $note  = function_exists('mb_substr') ? mb_substr($noteRaw, 0, 200) : substr($noteRaw, 0, 200);
            $batch = bin2hex(random_bytes(6));
            if ($days < 0) {
                $expires = 0; // 永久
            } else {
                // 显式按系统配置时区计算：到期日的 23:59:59
                $tz = new DateTimeZone(setting('timezone', 'Asia/Shanghai'));
                $expires = (new DateTime('today ' . max($days, 0) . ' days', $tz))
                    ->setTime(23, 59, 59)->getTimestamp();
            }

            for ($i = 0; $i < $count; $i++) {
                do { $key = generate_key($keyLen); }
                while (find_card_by_key($key));
                db_insert(
                    'INSERT INTO cards(card_key, batch, note, expires_at, created_at)
                     VALUES(:k,:b,:n,:e,:t)',
                    ['k' => $key, 'b' => $batch, 'n' => $note, 'e' => $expires, 't' => now()]
                );
            }
            add_log(null, null, 'generate', "批量 {$batch} 生成 {$count} 张，" . ($expires ? '到期 ' . date('Y-m-d', $expires) : '永久') . ($note ? "，备注：{$note}" : ''), true);
            $_SESSION['last_batch'] = $batch;
            flash('ok', "成功生成 {$count} 张卡密。");
            redirect('admin.php?p=cards&batch=' . $batch);

        case 'ban':
        case 'unban':
            $id = (int)($_POST['id'] ?? 0);
            $c = db_one('SELECT * FROM cards WHERE id=:id', ['id' => $id]);
            if ($c) {
                $ban = $action === 'ban' ? 1 : 0;
                db_exec('UPDATE cards SET banned=:b WHERE id=:id', ['b' => $ban, 'id' => $id]);
                add_log($id, $c['card_key'], $action, $ban ? '管理员封禁' : '管理员解封', true);
                flash('ok', $ban ? '已封禁该卡密，立即失效。' : '已解封。');
            }
            break;

        case 'delete':
            $id = (int)($_POST['id'] ?? 0);
            $c = db_one('SELECT * FROM cards WHERE id=:id', ['id' => $id]);
            if ($c) {
                // 必须先写日志（此时卡片仍存在，满足外键），再删除卡片
                add_log($id, $c['card_key'], 'delete', '管理员删除卡密', true);
                db_exec('DELETE FROM cards WHERE id=:id', ['id' => $id]); // 日志 card_id 经 FK SET NULL，快照保留
                flash('ok', '卡密已删除（历史日志保留）。');
            }
            break;

        case 'batch_op':
            $ids = array_values(array_filter(array_map('intval', (array)($_POST['ids'] ?? []))));
            $op = $_POST['op'] ?? '';
            if ($ids && in_array($op, ['ban', 'unban', 'delete'], true)) {
                $place = implode(',', array_fill(0, count($ids), '?'));
                $rows = db_all("SELECT * FROM cards WHERE id IN ($place)", $ids);
                // 删除前先写日志（外键约束要求卡片仍存在）
                foreach ($rows as $r) {
                    add_log((int)$r['id'], $r['card_key'], $op === 'delete' ? 'delete' : $op,
                        '批量操作：' . $op, true);
                }
                if ($op === 'delete') {
                    db_exec("DELETE FROM cards WHERE id IN ($place)", $ids);
                } else {
                    db_exec("UPDATE cards SET banned=? WHERE id IN ($place)",
                        array_merge([$op === 'ban' ? 1 : 0], $ids));
                }
                flash('ok', '批量操作完成，共 ' . count($rows) . ' 张。');
            } else {
                flash('err', '未选择卡密或操作无效。');
            }
            break;

        case 'settings':
            set_setting('site_name', trim($_POST['site_name'] ?? '') ?: APP_NAME);
            set_setting('notice', trim($_POST['notice'] ?? ''));
            $tz = trim($_POST['timezone'] ?? 'Asia/Shanghai');
            @date_default_timezone_set($tz);
            set_setting('timezone', $tz);
            add_log(null, null, 'settings', '修改站点设置', true);
            flash('ok', '设置已保存。');
            break;

        case 'password':
            $old = $_POST['old_password'] ?? '';
            $new = $_POST['new_password'] ?? '';
            $new2 = $_POST['new_password2'] ?? '';
            if (!password_verify($old, $adminHash)) {
                flash('err', '原密码不正确。');
            } elseif (strlen($new) < 8) {
                flash('err', '新密码长度至少 8 位。');
            } elseif ($new !== $new2) {
                flash('err', '两次输入的新密码不一致。');
            } else {
                $hash = password_hash($new, PASSWORD_DEFAULT);
                $tmp = DATA_DIR . '/config.tmp.php';
                file_put_contents($tmp, render_config($adminUser, $hash));
                if (file_get_contents($tmp) !== false) {
                    rename($tmp, CONFIG_PATH);
                    add_log(null, null, 'password', '管理员修改登录密码', true);
                    flash('ok', '密码已修改，下次登录生效。');
                } else {
                    flash('err', '配置文件写入失败，请检查 data 目录权限。');
                }
            }
            break;

        case 'upload':
            if (empty($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
                $code = $_FILES['file']['error'] ?? -1;
                $msg = [UPLOAD_ERR_INI_SIZE => '文件超过 php.ini 上传限制', UPLOAD_ERR_FORM_SIZE => '文件超过表单限制',
                        UPLOAD_ERR_PARTIAL => '文件仅部分上传', UPLOAD_ERR_NO_FILE => '未选择文件',
                        UPLOAD_ERR_NO_TMP_DIR => '服务器缺少临时目录', UPLOAD_ERR_CANT_WRITE => '服务器写入失败'];
                flash('err', '上传失败：' . ($msg[$code] ?? '错误码 ' . $code));
                break;
            }
            $fname = safe_filename($_FILES['file']['name']);
            if (!$fname) {
                flash('err', '文件名含非法字符（仅允许中英文、数字、点、下划线、连字符）。');
                break;
            }
            $dest = DOWNLOADS_DIR . '/' . $fname;
            if (is_file($dest)) {
                $p = pathinfo($fname);
                $fname = ($p['filename'] ?? 'file') . '_' . date('YmdHis') . '.' . ($p['extension'] ?? 'bin');
                $dest = DOWNLOADS_DIR . '/' . $fname;
            }
            if (!is_dir(DOWNLOADS_DIR) || !is_writable(DOWNLOADS_DIR)) {
                flash('err', 'downloads 目录不存在或不可写。');
                break;
            }
            if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
                add_log(null, null, 'upload', "上传安装包 {$fname}（" . hsize((int)filesize($dest)) . '）', true);
                flash('ok', "安装包 {$fname} 上传成功。");
            } else {
                flash('err', '文件保存失败，请检查目录权限。');
            }
            break;

        case 'delete_file':
            $fname = safe_filename($_POST['file'] ?? '');
            if ($fname && is_file(DOWNLOADS_DIR . '/' . $fname)) {
                @unlink(DOWNLOADS_DIR . '/' . $fname);
                add_log(null, null, 'delete_file', '删除安装包 ' . $fname, true);
                flash('ok', "已删除 {$fname}。");
            }
            break;

        default:
            flash('err', '未知操作。');
    }
    $back = $_POST['back'] ?? ('admin.php?p=' . ($_GET['p'] ?? 'dashboard'));
    redirect($back);
}

/* ================= CSV 导出（GET，需登录） ================= */
if (($_GET['export'] ?? '') === 'cards') {
    $where = build_card_where($_GET);
    $rows = db_all("SELECT * FROM cards {$where['sql']} ORDER BY created_at DESC, id DESC", $where['params']);
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="cards_' . date('YmdHis') . '.csv"');
    $out = fopen('php://output', 'wb');
    fwrite($out, "\xEF\xBB\xBF"); // UTF-8 BOM，Excel 防乱码
    fputcsv($out, ['卡密', '状态', '有效期至', '备注', '使用次数', '下载次数', '最后使用', '生成时间', '批次']);
    foreach ($rows as $r) {
        fputcsv($out, [
            format_key($r['card_key']), status_label(card_status($r)),
            (int)$r['expires_at'] === 0 ? '永久' : date('Y-m-d H:i', (int)$r['expires_at']),
            $r['note'], (int)$r['use_count'], (int)$r['download_count'],
            $r['last_used_at'] ? date('Y-m-d H:i', (int)$r['last_used_at']) : '',
            date('Y-m-d H:i', (int)$r['created_at']), $r['batch'],
        ]);
    }
    fclose($out);
    exit;
}
if (($_GET['export'] ?? '') === 'logs') {
    $where = build_log_where($_GET);
    $rows = db_all("SELECT * FROM logs {$where['sql']} ORDER BY id DESC LIMIT 50000", $where['params']);
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="logs_' . date('YmdHis') . '.csv"');
    $out = fopen('php://output', 'wb');
    fwrite($out, "\xEF\xBB\xBF");
    fputcsv($out, ['时间', '来源', '动作', '卡密', '详情', 'IP']);
    foreach ($rows as $r) {
        fputcsv($out, [
            date('Y-m-d H:i:s', (int)$r['created_at']),
            $r['is_admin'] ? '管理员' : '用户',
            action_label($r['action']),
            $r['card_key_snapshot'] ? format_key($r['card_key_snapshot']) : '',
            $r['detail'], $r['ip'],
        ]);
    }
    fclose($out);
    exit;
}

/* ================= 查询条件构造 ================= */
function build_card_where(array $q): array {
    $sql = ''; $p = [];
    if (!empty($q['batch'])) { $sql .= ' AND batch=:batch'; $p['batch'] = $q['batch']; }
    if (($q['status'] ?? 'all') !== 'all' && $q['status'] !== '') {
        $st = $q['status'];
        if ($st === 'active')  { $sql .= ' AND banned=0 AND (expires_at=0 OR expires_at>=:now)'; $p['now'] = now(); }
        if ($st === 'expired') { $sql .= ' AND banned=0 AND expires_at!=0 AND expires_at<:now'; $p['now'] = now(); }
        if ($st === 'banned')  { $sql .= ' AND banned=1'; }
    }
    $kw = trim($q['q'] ?? '');
    if ($kw !== '') {
        $sql .= ' AND (card_key LIKE :kw OR note LIKE :nkw)';
        $p['kw'] = '%' . normalize_key($kw) . '%';
        $p['nkw'] = '%' . $kw . '%';
    }
    return ['sql' => $sql ? ' WHERE ' . ltrim($sql, ' AND') : '', 'params' => $p];
}

function build_log_where(array $q): array {
    $sql = ''; $p = [];
    if (!empty($q['action'])) { $sql .= ' AND action=:a'; $p['a'] = $q['action']; }
    if (($q['scope'] ?? 'all') === 'admin') { $sql .= ' AND is_admin=1'; }
    if (($q['scope'] ?? 'all') === 'user')  { $sql .= ' AND is_admin=0'; }
    if (trim($q['q'] ?? '') !== '') {
        $sql .= ' AND (card_key_snapshot LIKE :kw OR detail LIKE :kw2 OR ip LIKE :kw3)';
        $kw = '%' . trim($q['q']) . '%';
        $p['kw'] = $kw; $p['kw2'] = $kw; $p['kw3'] = $kw;
    }
    return ['sql' => $sql ? ' WHERE ' . ltrim($sql, ' AND') : '', 'params' => $p];
}

function render_config(string $user, string $hash): string {
    $user = var_export($user, true);
    return "<?php\n// 本文件由系统生成，请勿手工泄露\nreturn [\n"
        . "    'admin_user' => {$user},\n"
        . "    'admin_hash' => " . var_export($hash, true) . ",\n"
        . "];\n";
}

/* ================= 页面渲染 ================= */
$page = $_GET['p'] ?? 'dashboard';
$tabs = ['dashboard' => '仪表盘', 'cards' => '卡密管理', 'logs' => '使用日志',
         'packages' => '安装包', 'check' => '部署自检', 'settings' => '系统设置'];

ob_start();

switch ($page) {

case 'dashboard':
    $now = now();
    $stat = db_one("SELECT
        SUM(CASE WHEN banned=0 AND (expires_at=0 OR expires_at>=$now) THEN 1 ELSE 0 END) AS active,
        SUM(CASE WHEN banned=0 AND expires_at!=0 AND expires_at<$now THEN 1 ELSE 0 END) AS expired,
        SUM(banned) AS banned,
        COUNT(*) AS total,
        COALESCE(SUM(use_count),0) AS uses,
        COALESCE(SUM(download_count),0) AS downloads
        FROM cards") ?: [];
    $todayDl = (int)(db_one('SELECT COUNT(*) c FROM logs WHERE action="download" AND created_at>=:t',
        ['t' => $tzToday])['c'] ?? 0);
    $todayFail = (int)(db_one('SELECT COUNT(*) c FROM logs WHERE action="verify_fail" AND created_at>=:t',
        ['t' => $tzToday])['c'] ?? 0);
    $tzToday = (new DateTime('today', new DateTimeZone(setting('timezone', 'Asia/Shanghai'))))->getTimestamp();
    $lastLogs = db_all('SELECT * FROM logs ORDER BY id DESC LIMIT 8');
    ?>
    <h1 class="page-title">仪表盘</h1>
    <div class="stats">
      <div class="stat"><div class="num"><?= (int)$stat['active'] ?></div><div class="lbl">有效卡密</div></div>
      <div class="stat"><div class="num" style="color:var(--muted)"><?= (int)$stat['expired'] ?></div><div class="lbl">已过期</div></div>
      <div class="stat"><div class="num" style="color:var(--err)"><?= (int)$stat['banned'] ?></div><div class="lbl">已封禁</div></div>
      <div class="stat"><div class="num"><?= (int)$stat['total'] ?></div><div class="lbl">卡密总数</div></div>
      <div class="stat"><div class="num"><?= $todayDl ?></div><div class="lbl">今日下载次数</div></div>
      <div class="stat"><div class="num" style="color:var(--warn)"><?= $todayFail ?></div><div class="lbl">今日验证失败</div></div>
    </div>
    <div class="card">
      <h2>最近操作</h2>
      <div class="table-scroll"><table>
        <thead><tr><th>时间</th><th>来源</th><th>动作</th><th>卡密</th><th>详情</th><th>IP</th></tr></thead>
        <tbody>
        <?php foreach ($lastLogs as $l): ?>
          <tr>
            <td class="nowrap"><?= e(fmt_date((int)$l['created_at'])) ?></td>
            <td><?= $l['is_admin'] ? '管理员' : '用户' ?></td>
            <td class="nowrap"><?= e(action_label($l['action'])) ?></td>
            <td class="key-mono"><?= $l['card_key_snapshot'] ? e(format_key($l['card_key_snapshot'])) : '-' ?></td>
            <td><?= e($l['detail']) ?></td>
            <td class="nowrap muted"><?= e($l['ip']) ?></td>
          </tr>
        <?php endforeach ?>
        <?php if (!$lastLogs): ?><tr><td colspan="6" class="center muted">暂无日志</td></tr><?php endif; ?>
        </tbody></table></div>
    </div>
    <?php
    break;

case 'cards':
    $perPage = 30;
    $pageNo = max(1, (int)($_GET['page'] ?? 1));
    $where = build_card_where($_GET);
    $total = (int)(db_one("SELECT COUNT(*) c FROM cards {$where['sql']}", $where['params'])['c'] ?? 0);
    $totalPages = max(1, (int)ceil($total / $perPage));
    $pageNo = min($pageNo, $totalPages);
    $rows = db_all(
        "SELECT * FROM cards {$where['sql']} ORDER BY created_at DESC, id DESC LIMIT :lim OFFSET :off",
        $where['params'] + ['lim' => $perPage, 'off' => ($pageNo - 1) * $perPage]
    );
    $batch = $_GET['batch'] ?? '';
    $showBatch = $batch !== '' && ($_SESSION['last_batch'] ?? '') === $batch;
    unset($_SESSION['last_batch']);
    $exportQuery = http_build_query(array_diff_key($_GET, ['p' => 1, 'page' => 1]) + ['export' => 'cards']);
    ?>
    <h1 class="page-title">卡密管理</h1>

    <?php if ($showBatch):
        $newRows = db_all('SELECT * FROM cards WHERE batch=:b ORDER BY id', ['b' => $batch]); ?>
    <div class="card">
      <h2>本批新生成的卡密（共 <?= count($newRows) ?> 张，请立即保存）</h2>
      <div class="alert warn">关闭后卡密仍可在列表中查看；建议点“导出本批 CSV”分发给用户。</div>
      <div class="table-scroll"><table>
        <thead><tr><th>卡密</th><th>有效期至</th><th>备注</th><th>状态</th></tr></thead><tbody>
        <?php foreach ($newRows as $r): ?>
        <tr>
          <td class="key-mono"><?= e(format_key($r['card_key'])) ?></td>
          <td class="nowrap"><?= (int)$r['expires_at'] === 0 ? '永久' : e(date('Y-m-d H:i', (int)$r['expires_at'])) ?></td>
          <td><?= e($r['note']) ?></td>
          <td><span class="badge <?= e(card_status($r)) ?>"><?= e(status_label(card_status($r))) ?></span></td>
        </tr>
        <?php endforeach; ?>
        </tbody></table></div>
        <div class="actions">
          <a class="btn" href="?export=cards&batch=<?= e($batch) ?>">导出本批 CSV</a>
        </div>
    </div>
    <?php endif; ?>

    <div class="card">
      <h2>批量生成</h2>
      <form method="post" action="admin.php">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="generate">
        <div class="form-row">
          <div><label>生成数量</label><input type="number" name="count" value="10" min="1" max="500"></div>
          <div><label>有效天数</label><input type="number" name="valid_days" value="30" min="-1">
            <div class="hint">自今日起 N 天；填 -1 为永久有效</div></div>
          <div><label>卡密长度</label><input type="number" name="key_len" value="20" min="12" max="32"></div>
          <div style="flex:2"><label>备注（可选）</label><input type="text" name="note" maxlength="200" placeholder="如：9月推广批次"></div>
        </div>
        <div class="actions"><button class="btn" type="submit">生成卡密</button></div>
      </form>
    </div>

    <div class="card">
      <h2>卡密列表（<?= $total ?>）</h2>
      <form method="get" class="filters">
        <input type="hidden" name="p" value="cards">
        <?php if ($batch): ?><input type="hidden" name="batch" value="<?= e($batch) ?>"><?php endif; ?>
        <div><label>状态</label>
          <select name="status">
            <?php foreach (['all' => '全部', 'active' => '正常', 'expired' => '已过期', 'banned' => '已封禁'] as $k => $v): ?>
              <option value="<?= $k ?>" <?= ($_GET['status'] ?? 'all') === $k ? 'selected' : '' ?>><?= $v ?></option>
            <?php endforeach ?>
          </select>
        </div>
        <div style="flex:2"><label>搜索（卡密 / 备注）</label>
          <input type="text" name="q" value="<?= e($_GET['q'] ?? '') ?>" placeholder="输入卡密片段"></div>
        <button class="btn sm" type="submit">筛选</button>
        <a class="btn sm secondary" href="?p=cards">重置</a>
        <a class="btn sm secondary" href="?<?= e($exportQuery) ?>">导出 CSV</a>
      </form>

      <form id="batchform" method="post" action="admin.php?p=cards">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="batch_op">
        <input type="hidden" name="op" id="batchop" value="">
        <div class="actions" style="margin-top:0">
          <button class="btn sm secondary" type="button" onclick="setOp('ban')">批量封禁</button>
          <button class="btn sm secondary" type="button" onclick="setOp('unban')">批量解封</button>
          <button class="btn sm danger" type="button" onclick="setOp('delete')">批量删除</button>
        </div>
        <div class="table-scroll"><table>
          <thead><tr>
            <th><input type="checkbox" onclick="document.querySelectorAll('.ck').forEach(c=>c.checked=this.checked)"></th>
            <th>卡密</th><th>状态</th><th>有效期至</th><th>备注</th>
            <th>验证/下载</th><th>最后使用</th><th>生成时间</th><th>操作</th>
          </tr></thead>
          <tbody>
          <?php foreach ($rows as $r): $st = card_status($r); ?>
            <tr>
              <td><input type="checkbox" class="ck" name="ids[]" value="<?= (int)$r['id'] ?>"></td>
              <td class="key-mono"><?= e(format_key($r['card_key'])) ?></td>
              <td><span class="badge <?= e($st) ?>"><?= e(status_label($st)) ?></span></td>
              <td class="nowrap">
                <?php if ((int)$r['expires_at'] === 0): ?>永久
                <?php else: ?><?= e(date('Y-m-d H:i', (int)$r['expires_at'])) ?>
                  <?php if ($st === 'active'): ?><div class="detail">剩 <?= (int)ceil(((int)$r['expires_at'] - now()) / 86400) ?> 天</div><?php endif; ?>
                <?php endif; ?>
              </td>
              <td><?= e($r['note']) ?></td>
              <td class="nowrap"><?= (int)$r['use_count'] ?> / <?= (int)$r['download_count'] ?></td>
              <td class="nowrap muted"><?= $r['last_used_at'] ? e(fmt_date((int)$r['last_used_at'])) : '-' ?></td>
              <td class="nowrap muted"><?= e(fmt_date((int)$r['created_at'])) ?></td>
              <td class="nowrap">
                <?php if ($st === 'banned'): ?>
                  <form method="post" style="display:inline"><?= csrf_field() ?>
                    <input type="hidden" name="action" value="unban"><input type="hidden" name="id" value="<?= (int)$r['id'] ?>">
                    <button class="btn sm secondary">解封</button></form>
                <?php else: ?>
                  <form method="post" style="display:inline"><?= csrf_field() ?>
                    <input type="hidden" name="action" value="ban"><input type="hidden" name="id" value="<?= (int)$r['id'] ?>">
                    <button class="btn sm secondary" onclick="return confirm('确定封禁该卡密？封禁后立即失效。')">封禁</button></form>
                <?php endif; ?>
                <form method="post" style="display:inline"><?= csrf_field() ?>
                  <input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?= (int)$r['id'] ?>">
                  <button class="btn sm danger" onclick="return confirm('确定删除？删除后该卡密立即无法使用，历史日志保留。')">删除</button></form>
              </td>
            </tr>
          <?php endforeach; ?>
          <?php if (!$rows): ?><tr><td colspan="9" class="center muted">没有匹配的卡密</td></tr><?php endif; ?>
          </tbody></table></div>
      </form>
      <?= render_pagination($pageNo, $totalPages, array_intersect_key($_GET, ['status'=>1,'q'=>1,'batch'=>1])) ?>
    </div>
    <script>
    function setOp(op){
      var n=document.querySelectorAll('.ck:checked').length;
      if(!n){alert('请先勾选卡密');return;}
      var msg=op==='delete'?'确定删除选中的 '+n+' 张卡密？此操作不可恢复。':'确定对选中的 '+n+' 张卡密执行'+(op==='ban'?'封禁':'解封')+'？';
      if(confirm(msg)){document.getElementById('batchop').value=op;document.getElementById('batchform').submit();}
    }
    </script>
    <?php
    break;

case 'logs':
    $perPage = 50;
    $pageNo = max(1, (int)($_GET['page'] ?? 1));
    $where = build_log_where($_GET);
    $total = (int)(db_one("SELECT COUNT(*) c FROM logs {$where['sql']}", $where['params'])['c'] ?? 0);
    $totalPages = max(1, (int)ceil($total / $perPage));
    $pageNo = min($pageNo, $totalPages);
    $rows = db_all("SELECT * FROM logs {$where['sql']} ORDER BY id DESC LIMIT :lim OFFSET :off",
        $where['params'] + ['lim' => $perPage, 'off' => ($pageNo - 1) * $perPage]);
    $actions = array_unique(array_map(fn($r) => $r['action'],
        db_all('SELECT DISTINCT action FROM logs')));
    $exportQuery = http_build_query(array_diff_key($_GET, ['p'=>1,'page'=>1]) + ['export' => 'logs']);
    ?>
    <h1 class="page-title">使用日志</h1>
    <div class="card">
      <form method="get" class="filters">
        <input type="hidden" name="p" value="logs">
        <div><label>动作</label>
          <select name="action"><option value="">全部</option>
            <?php foreach ($actions as $a): ?>
              <option value="<?= e($a) ?>" <?= ($_GET['action'] ?? '') === $a ? 'selected' : '' ?>><?= e(action_label($a)) ?></option>
            <?php endforeach ?>
          </select>
        </div>
        <div><label>来源</label>
          <select name="scope">
            <?php foreach (['all' => '全部', 'user' => '用户', 'admin' => '管理员'] as $k => $v): ?>
              <option value="<?= $k ?>" <?= ($_GET['scope'] ?? 'all') === $k ? 'selected' : '' ?>><?= $v ?></option>
            <?php endforeach ?>
          </select>
        </div>
        <div style="flex:2"><label>关键词（卡密 / 详情 / IP）</label>
          <input type="text" name="q" value="<?= e($_GET['q'] ?? '') ?>"></div>
        <button class="btn sm">筛选</button>
        <a class="btn sm secondary" href="?p=logs">重置</a>
        <a class="btn sm secondary" href="?<?= e($exportQuery) ?>">导出 CSV（上限 5 万条）</a>
      </form>
      <div class="table-scroll"><table>
        <thead><tr><th>时间</th><th>来源</th><th>动作</th><th>卡密</th><th>详情</th><th>IP</th></tr></thead>
        <tbody>
        <?php foreach ($rows as $l): ?>
          <tr>
            <td class="nowrap"><?= e(fmt_date((int)$l['created_at'])) ?></td>
            <td><?= $l['is_admin'] ? '管理员' : '用户' ?></td>
            <td class="nowrap"><?= e(action_label($l['action'])) ?></td>
            <td class="key-mono"><?= $l['card_key_snapshot'] ? e(format_key($l['card_key_snapshot'])) : '-' ?></td>
            <td><?= e($l['detail']) ?></td>
            <td class="nowrap muted"><?= e($l['ip']) ?></td>
          </tr>
        <?php endforeach; ?>
        <?php if (!$rows): ?><tr><td colspan="6" class="center muted">没有日志记录</td></tr><?php endif; ?>
        </tbody></table></div>
      <?= render_pagination($pageNo, $totalPages, array_intersect_key($_GET, ['action'=>1,'scope'=>1,'q'=>1])) ?>
    </div>
    <?php
    break;

case 'packages':
    $files = package_files();
    $postMax = ini_get('post_max_size');
    ?>
    <h1 class="page-title">安装包管理</h1>
    <div class="card">
      <h2>上传安装包</h2>
      <form method="post" action="admin.php?p=packages" enctype="multipart/form-data">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="upload">
        <label>选择文件</label>
        <input type="file" name="file" required>
        <div class="hint">文件名仅支持中英文、数字、点、下划线和连字符；重名文件自动加时间戳。
          服务器限制 post_max_size=<?= e($postMax) ?>，大文件请用 SCP/FTP 上传到 downloads/ 目录。</div>
        <div class="actions"><button class="btn" type="submit">上传</button></div>
      </form>
    </div>
    <div class="card">
      <h2>当前安装包（<?= count($files) ?>）</h2>
      <div class="table-scroll"><table>
        <thead><tr><th>文件名</th><th>大小</th><th>上传/修改时间</th><th>操作</th></tr></thead>
        <tbody>
        <?php foreach ($files as $f): ?>
          <tr>
            <td><?= e($f['name']) ?></td>
            <td class="nowrap"><?= e(hsize($f['size'])) ?></td>
            <td class="nowrap muted"><?= e(date('Y-m-d H:i', $f['mtime'])) ?></td>
            <td class="nowrap">
              <form method="post" action="admin.php?p=packages" style="display:inline"><?= csrf_field() ?>
                <input type="hidden" name="action" value="delete_file">
                <input type="hidden" name="file" value="<?= e($f['name']) ?>">
                <button class="btn sm danger" onclick="return confirm('确定删除安装包 <?= e($f['name']) ?>？')">删除</button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
        <?php if (!$files): ?><tr><td colspan="4" class="center muted">downloads 目录中暂无安装包</td></tr><?php endif; ?>
        </tbody></table></div>
    </div>
    <?php
    break;

case 'check':
    $result = run_checks();
    ?>
    <h1 class="page-title">部署自检</h1>
    <div class="alert <?= $result['pass'] ? 'ok' : 'err' ?>">
      <?php if ($result['pass']): ?>全部硬性检查通过，系统可以正常运行。
      请留意下方警告项（Nginx 规则、HTTPS、install.php 等）。<?php else: ?>存在未通过的硬性检查项（✗），请按提示修复后再投入使用。<?php endif; ?>
    </div>
    <div class="card"><?= render_check_items($result['items']) ?>
      <div class="actions"><a class="btn secondary" href="?p=check">重新检查</a></div>
    </div>
    <?php
    break;

case 'settings':
    ?>
    <h1 class="page-title">系统设置</h1>
    <div class="card">
      <h2>站点设置</h2>
      <form method="post" action="admin.php?p=settings">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="settings">
        <label>站点名称</label>
        <input type="text" name="site_name" value="<?= e(setting('site_name', APP_NAME)) ?>">
        <label>下载页公告（可选）</label>
        <textarea name="notice" placeholder="例如：安装前请先关闭杀毒软件…"><?= e(setting('notice', '')) ?></textarea>
        <label>时区</label>
        <input type="text" name="timezone" value="<?= e(setting('timezone', 'Asia/Shanghai')) ?>">
        <div class="hint">PHP 时区标识符，如 Asia/Shanghai、UTC。</div>
        <div class="actions"><button class="btn">保存设置</button></div>
      </form>
    </div>
    <div class="card">
      <h2>修改管理员密码</h2>
      <form method="post" action="admin.php?p=settings">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="password">
        <label>原密码</label><input type="password" name="old_password" required autocomplete="current-password">
        <div class="form-row">
          <div><label>新密码（至少 8 位）</label><input type="password" name="new_password" required minlength="8" autocomplete="new-password"></div>
          <div><label>确认新密码</label><input type="password" name="new_password2" required autocomplete="new-password"></div>
        </div>
        <div class="actions"><button class="btn">修改密码</button></div>
      </form>
    </div>
    <?php
    break;

default:
    http_response_code(404);
    echo '<p>页面不存在。</p>';
}

$content = ob_get_clean();
?>
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>管理后台 - <?= e(setting('site_name', APP_NAME)) ?></title>
<link rel="stylesheet" href="<?= e(url('assets/style.css')) ?>">
</head>
<body>
<div class="topbar">
  <div class="in">
    <span class="brand">🔑 卡密后台</span>
    <nav>
      <?php foreach ($tabs as $k => $v): ?>
        <a href="?p=<?= $k ?>" class="<?= $page === $k ? 'active' : '' ?>"><?= $v ?></a>
      <?php endforeach; ?>
    </nav>
    <span class="spacer"></span>
    <span class="who"><?= e($_SESSION['admin_user'] ?? 'admin') ?></span>
    <form method="post" style="display:inline"><?= csrf_field() ?>
      <input type="hidden" name="action" value="logout">
      <button class="btn sm secondary" type="submit">退出</button>
    </form>
  </div>
</div>
<div class="wrap">
  <?php foreach (take_flash() as $f): ?>
    <div class="alert <?= e($f['type']) ?>"><?= e($f['msg']) ?></div>
  <?php endforeach; ?>
  <?= $content ?>
</div>
</body></html>
