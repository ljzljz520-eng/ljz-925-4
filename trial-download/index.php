<?php
require __DIR__ . '/lib/core.php';

if (!is_file(CONFIG_PATH)) {
    http_response_code(503);
    echo '系统尚未安装，请先访问 <a href="install.php">install.php</a>。';
    exit;
}

date_default_timezone_set(setting('timezone', 'Asia/Shanghai'));
boot_session();

$card = authed_card();
$input = '';

// 处理卡密提交
if (!$card && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'verify') {
    csrf_check();
    $input = trim($_POST['card_key'] ?? '');
    $norm = normalize_key($input);

    if ($norm === '') {
        flash('err', '请输入卡密。');
    } elseif (!rate_check('verify', VERIFY_MAX_FAILS, VERIFY_LOCK_SECONDS)) {
        flash('err', '尝试失败次数过多，请 ' . round(VERIFY_LOCK_SECONDS / 60) . ' 分钟后再试。');
        add_log(null, $norm, 'verify_fail', '触发限流锁定');
    } else {
        $row = find_card_by_key($norm);
        if (!$row) {
            rate_hit('verify');
            add_log(null, $norm, 'verify_fail', '卡密不存在');
            flash('err', '卡密无效，请检查后重新输入。');
        } elseif (card_status($row) === 'banned') {
            rate_hit('verify');
            add_log((int)$row['id'], $norm, 'verify_fail', '卡密已被封禁');
            flash('err', '该卡密已被封禁，无法使用。');
        } elseif (card_status($row) === 'expired') {
            rate_hit('verify');
            add_log((int)$row['id'], $norm, 'verify_fail', '卡密已过期（到期 ' . date('Y-m-d', (int)$row['expires_at']) . '）');
            flash('err', '该卡密已于 ' . date('Y-m-d', (int)$row['expires_at']) . ' 到期。');
        } else {
            rate_clear('verify');
            set_download_auth((int)$row['id']);
            db_exec(
                'UPDATE cards SET use_count=use_count+1, last_used_at=:t, last_ip=:ip WHERE id=:id',
                ['t' => now(), 'ip' => client_ip(), 'id' => (int)$row['id']]
            );
            add_log((int)$row['id'], $norm, 'verify_ok', '验证通过，进入下载页');
            header('Location: ' . url('index.php'));
            exit;
        }
    }
}

// 退出（清除授权）
if ($card && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'logout') {
    csrf_check();
    clear_download_auth();
    header('Location: ' . url('index.php'));
    exit;
}

$card = authed_card();
$files = package_files();
$siteName = setting('site_name', APP_NAME);
$notice = setting('notice', '');
?>
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= e($siteName) ?></title>
<link rel="stylesheet" href="<?= e(url('assets/style.css')) ?>">
</head>
<body>
<div class="topbar">
  <div class="in">
    <span class="brand"><?= e($siteName) ?></span>
    <span class="spacer"></span>
    <a class="who" href="<?= e(url('admin.php')) ?>">管理后台</a>
  </div>
</div>
<div class="wrap narrow">

  <?php foreach (take_flash() as $f): ?>
    <div class="alert <?= e($f['type']) ?>"><?= e($f['msg']) ?></div>
  <?php endforeach ?>

  <?php if (!$card): ?>
  <div class="card">
    <h2>输入试用卡密</h2>
    <p class="muted" style="margin-top:0">请输入您收到的卡密（不区分大小写，含或不含连字符均可），验证通过后即可下载试用安装包。</p>
    <form method="post" autocomplete="off">
      <?= csrf_field() ?>
      <input type="hidden" name="action" value="verify">
      <label for="card_key">卡密</label>
      <input type="text" id="card_key" name="card_key" value="<?= e($input) ?>"
             placeholder="例如 XXXX-XXXX-XXXX-XXXX" autofocus required
             style="font-family:ui-monospace,monospace;letter-spacing:1px">
      <div class="actions">
        <button class="btn" type="submit">验证并下载</button>
      </div>
    </form>
  </div>
  <?php else:
    $expiry = (int)$card['expires_at'];
    $daysLeft = $expiry === 0 ? null : (int)ceil(($expiry - now()) / 86400);
  ?>
  <div class="card dl-hero">
    <div class="ico">📦</div>
    <h2>验证通过</h2>
    <p style="margin:4px 0 14px">
      卡密 <span class="key-mono"><?= e(format_key($card['card_key'])) ?></span>
    </p>
    <div class="form-row" style="text-align:left">
      <div>
        <label>有效期至</label>
        <div><?= $expiry === 0 ? '永久有效' : e(date('Y-m-d H:i', $expiry)) ?>
          <?php if ($daysLeft !== null): ?>
            <span class="badge <?= $daysLeft <= 3 ? 'banned' : 'active' ?>">剩 <?= max($daysLeft, 0) ?> 天</span>
          <?php endif ?>
        </div>
      </div>
      <div>
        <label>已使用次数</label>
        <div><?= (int)$card['use_count'] ?> 次</div>
      </div>
    </div>
  </div>

  <?php if ($notice !== ''): ?>
  <div class="alert info"><?= nl2br(e($notice)) ?></div>
  <?php endif ?>

  <div class="card">
    <h2>安装包下载</h2>
    <?php if (!$files): ?>
      <p class="muted">暂未上传任何安装包，请联系管理员。</p>
    <?php else: ?>
      <div class="table-scroll">
      <table>
        <thead><tr><th>文件名</th><th>大小</th><th>更新时间</th><th></th></tr></thead>
        <tbody>
        <?php foreach ($files as $f): ?>
          <tr>
            <td><?= e($f['name']) ?></td>
            <td class="nowrap"><?= e(hsize($f['size'])) ?></td>
            <td class="nowrap muted"><?= e(date('Y-m-d H:i', $f['mtime'])) ?></td>
            <td class="nowrap">
              <a class="btn sm" href="<?= e(url('download.php?f=' . rawurlencode($f['name']))) ?>">⬇ 下载</a>
            </td>
          </tr>
        <?php endforeach ?>
        </tbody>
      </table>
      </div>
    <?php endif ?>
  </div>

  <form method="post" style="text-align:center">
    <?= csrf_field() ?>
    <input type="hidden" name="action" value="logout">
    <button class="btn secondary" type="submit">退出当前卡密</button>
  </form>
  <?php endif ?>

  <div class="footer">© <?= date('Y') ?> <?= e($siteName) ?></div>
</div>
</body>
</html>
