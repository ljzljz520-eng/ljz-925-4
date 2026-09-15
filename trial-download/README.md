# 卡密试用下载系统

一个「卡密验证后才能下载软件」的轻量门户。PHP + SQLite3，**上传即用**，无需 MySQL。

## 功能

- 🔑 **用户端**：输入卡密 → 校验通过 → 出现下载按钮；退出即收回下载权限
- ⏳ **到期自动失效**：过期、被封禁的卡密在每次验证/下载请求时实时判定，无需定时任务
- 🧾 **使用日志**：验证成功/失败、下载、封禁/解封/删除、管理员操作全部留痕（含 IP、时间、卡密快照），支持筛选与 CSV 导出
- 🛠 **管理后台**（admin.php）：
  - 批量生成卡密（数量、有效天数、长度、备注，自动去重）
  - 卡密列表筛选（正常/过期/封禁、关键词、批次）
  - 单张/批量 封禁、解封、删除
  - 导出全部/筛选结果/单批次 CSV（带 BOM，Excel 不乱码）
  - 安装包网页上传 / 删除，也可手动放入 `downloads/`
  - 修改站点名称、下载页公告、时区、管理员密码
  - **部署自检页**：PHP 版本、ext-sqlite3、目录权限、SQLite 真实读写探针、防直连、HTTPS 等
- 🛡 防爆破限流、CSRF 防护、会话 HttpOnly/SameSite、文件名穿越防护、数据库目录防直连

## 环境要求

- Linux + PHP **7.4+**（8.x 同样支持）
- PHP 扩展：**sqlite3（ext-sqlite3）**、session、openssl（random_bytes）、mbstring（建议）
- Apache 或 Nginx 均可

> 本系统使用的是 PHP 的 **SQLite3 扩展**（不是 pdo_sqlite）。Ubuntu/Debian：
> `sudo apt install php-sqlite3`；宝塔/1Panel：PHP 设置 → 安装 sqlite3 扩展。装后重启 php-fpm / Web 服务。

## 安装步骤（上传即用）

1. 将整个 `trial-download` 目录上传到站点目录（如 `/var/www/html/trial-download`）。
2. 设置目录权限（Web 运行用户常见为 `www-data`、`nginx`、`apache`，按实际替换）：

   ```bash
   cd /var/www/html/trial-download
   sudo chown -R www-data:www-data data downloads
   sudo chmod 750 data downloads
   ```

3. 浏览器访问 `http(s)://你的域名/install.php`，页面会先跑环境检查；全部硬性项通过后，创建管理员账号并点「开始安装」。
4. 安装完成后 **立即删除 install.php**：

   ```bash
   rm install.php
   ```

5. 后台进入「安装包」上传试用软件；「卡密管理」批量生成卡密并导出 CSV 发给用户。

## 部署自检（重点：sqlite3 权限）

后台「部署自检」页或安装向导会检查：

| 检查项 | 说明 |
|---|---|
| PHP 版本 | ≥ 7.4 |
| **SQLite3 扩展** | 未启用直接判定不可用，并给出安装命令 |
| **SQLite3 读写权限探针** | 在 `data/` 内建临时库，实际执行 建库→建表→写入→查询→删除，通过后清理。能真实暴露目录属主/挂载 noexec/SQLITE_BUSY 等问题 |
| `data` 目录 | 是否存在、是否可写、当前权限位 |
| `app.db` 文件 | 安装后检查数据库文件本身是否可写 |
| `downloads` 目录 | 影响网页上传（不可写时仍可 SCP 手动放文件） |
| 防直连 | Apache 检查 .htaccess；Nginx 给出配置提示 |
| 上传限制 / HTTPS | 信息与建议项 |

CLI 下也可快速验证扩展：`php -m | grep -i sqlite`（应看到 `sqlite3`）。

## Nginx 必做配置

Apache 下随包的 `.htaccess` 已自动保护 `data/`、`downloads/`；**Nginx 不识别 .htaccess**，需在 server 段中加入：

```nginx
# 数据库与配置文件：禁止任何外部访问
location ~* /(data|lib)/ {
    deny all;
    return 403;
}
# 安装包只允许通过 download.php 鉴权后下载，禁止直连
location ^~ /downloads/ {
    deny all;
    return 403;
}
location ~ /\.(db|db-wal|db-shm|ini|log|sh|sql)$ {
    deny all;
    return 403;
}
```

改完 `nginx -t && systemctl reload nginx`。

## 目录结构

```
trial-download/
├── index.php          # 用户：卡密输入 + 下载入口
├── download.php       # 鉴权后的文件下载（流式输出+日志计数）
├── admin.php          # 管理后台（单文件路由）
├── install.php        # 安装向导（安装后删除）
├── assets/style.css
├── lib/
│   ├── core.php       # DB/会话/卡密/限流/日志
│   └── checks.php     # 环境自检
├── data/              # 受保护：app.db / config.php（安装后生成）
└── downloads/         # 受保护：安装包放这里
```

## 常见问题

- **页面提示“SQLite3 扩展未启用”**：安装 `php-sqlite3` 并重启 php-fpm；多 PHP 版本时确认站点实际使用的版本。
- **探针失败 “unable to open database file”**：`data/` 属主不是 Web 用户或上级目录无进入权限，按上面的 chown/chmod 修复；检查磁盘是否被挂为只读。
- **上传大文件失败**：调大 php.ini 中 `upload_max_filesize`、`post_max_size`（后台自检页显示当前值），或改用 SCP/FTP 放入 `downloads/`，后台会自动列出。
- **到期卡还显示正常？**：过期状态按服务器当前时间实时计算，不写死字段；确认后台「系统设置」时区正确。
- **卡密删除后日志还在吗**：在。删除卡密仅删 cards 行，日志保留卡密快照以便审计。

## 安全建议

- 安装后立刻删除 `install.php`；`data/config.php` 含密码哈希，不要公开或提交 Git。
- 公网务必启用 HTTPS。
- 定期在后台导出日志与卡密备份；也可直接备份 `data/app.db`（WAL 模式下建议先停止写入或用 `sqlite3 app.db ".backup ..."`）。
