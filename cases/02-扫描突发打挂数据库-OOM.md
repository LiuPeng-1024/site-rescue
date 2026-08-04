# 案例 2：扫描器 60 请求/分钟打挂数据库（2026-08-02）

> 某猫粮比价站（宝塔+WP，阿里云 ECS 2GB）。状态：已结案。
> 价值：证明"被黑应急"不止挂马一种形态——**扫描流量本身就能打死小服务器**；site-rescue 产品叙事的重要案例。

## 现象

当天下午网站全站报 WordPress"数据库错误"（HTTP 500）。站长视角一头雾水：没被入侵、没改配置，数据库怎么"连不上"了。

## 根因（全证据链）

```
45.156.128.43（插件漏洞扫描器，逐个探 /wp-content/plugins/*/readme.txt）
16:56 一分钟 60 个请求（基线 1-3/分钟）
  → php-fpm（ondemand, max_children=30）瞬间开向 30 个子进程
  → 1870MB 内存耗尽 → OOM killer 连杀 mysqld 两次（dmesg 实录）
  → WP 报"数据库错误"
```

- dmesg：`Out of memory: Killed process (mysqld)` ×2（16:56:20/22）
- MySQL 错误日志：`Database was not shutdown normally! Starting crash recovery`
- 访问日志分钟级统计：16:56 突刺 60，前后分钟 1-3

## 处置（命令/操作）

1. `systemctl start mysqld` → InnoDB 崩溃自愈，站点恢复 200
2. `pm.max_children 30 → 10`（/www/server/php/82/etc/php-fpm.conf，先备份）→ 同类冲击只会慢不会死
3. 加固项全量复测（403/404/301 全绿，未因事故回退）
4. **当天顺势完成 Cloudflare 部署**（边缘质询拦截扫描路径）——把"扫描突发"从源站层面消掉

## 加固（本案例新增）

- CF 自定义规则"WP扫描防护"（托管质询：URI 命中 /wp-content/plugins/、xmlrpc.php、wp-admin、wp-login.php 即挑战）
- php-fpm 并发上限收紧（2GB 机型 pm.max_children ≤10）

## 复查结果

- CF 全链路 200 + CF-RAY ✓；质询规则 cf-mitigated: challenge ✓
- 待办：阿里云安全组收口（直连 IP 仍通）、bt 子域重建

## 给 runbook 的教训（五段式素材）

1. **"数据库错误"≠ 数据库坏了**——先查 dmesg 的 OOM 记录和 MySQL 是否被系统杀掉
2. **小内存机器（≤2GB）必须把 php-fpm 并发关小**，扫描器专杀这种配置
3. **突发流量查访问日志分钟级分布**，1-3 → 60 的突刺一眼定位
4. **扫描器流量是持续背景噪声**（本例三个 IP 日请求 495/296/162），边缘层（CF）拦截比源站硬扛便宜得多
5. **验证别信单一信号**：本站日志里出现过干扰性 200 记录，实测三遍（域名/HTTP/IP 直连）才确认防护真实状态
