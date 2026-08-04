# sr-repair — 被黑站修复安全骨架(三闸门)

一句话:帮你把"确定是马的文件"安全地清出网站。**它最大的卖点不是快,是不敢乱来** —— 所有修改动作必须硬闯三道代码级闸门,闯不过去就拒绝执行。

> ⚠️ 这是 v0.1 骨架版:只干一件事 —— 安全地隔离文件。数据库操作、改 wp-config、密码重置、核心重装都不做(那是 V1 正式版的事)。

## 三闸门是干什么的(为什么敢用它)

清理被黑的站,最大的风险不是清不干净,是**误删/清完站打不开了**。sr-repair 把三条安全规矩写死在代码里,不是提示,是强制:

- **闸门 1 · 备份门禁**:动手之前,先检查 24 小时内有没有有效备份(先看 `--backup-dir` 指定的目录,再看宝塔默认的 `/www/backup`)。**没有备份就拒绝执行**,并告诉你怎么备份。你也可以加 `--force-backup`,它会先把整站打包成 tar.gz 再继续。
- **闸门 2 · 隔离不删**:所有"清除"动作一律是**移动**,不是删除 —— 文件被移到网站目录之外的 `quarantine-日期时间/` 目录(默认 `/www/backup/quarantine-*`),同时写一份 `manifest.json` 留证:原路径、隔离路径、时间、命中原因、操作前的文件 hash,一项不少。代码里没有任何"直接删除站点文件"的调用,欢迎自己 grep 源码验证:`grep -nE "os\.remove|os\.unlink|shutil\.rmtree" sr-repair.py` 应该一个结果都没有。
- **闸门 3 · 健康回归**:操作前抓取首页 / wp-login / 一篇文章的快照(HTTP 状态 + 内容长度 + 关键标记),操作后复抓对比。一旦出现异常(状态码变 5xx、内容长度偏差超过 50%、关键标记消失),**自动按 manifest 把刚隔离的文件全部滚回原位**,并复测报告。

## 三步开跑(宝塔用户)

**第 1 步**:登录宝塔面板 → 左侧「终端」。

**第 2 步**:粘贴下面这行,把工具下载到服务器:

```bash
curl -o sr-repair.py https://raw.githubusercontent.com/LiuPeng-1024/site-rescue/main/repair/sr-repair.py
```

下载超时就在自己电脑打开该链接另存为,再用宝塔「文件」管理器上传(和 sr-scan 一样)。Python 3.6 以上都能跑,只用标准库。

**第 3 步**:先演习,再真干。演习只打印计划、什么都不动:

```bash
# 演习:看看它打算干什么(强烈建议任何操作都先跑一遍 --dry-run)
python3 sr-repair.py /www/wwwroot/mysite.com --from-report report.json --url https://mysite.com --dry-run

# 真干:把 sr-scan 报告里的【高危】文件全部隔离
python3 sr-repair.py /www/wwwroot/mysite.com --from-report report.json --url https://mysite.com
```

(`report.json` 就是之前跑 [sr-scan](../scan/) 时 `--json report.json` 生成的那份。)

## 四种用法

```bash
# 1) 按扫描报告隔离:报告里所有【高危】文件过三闸门
python3 sr-repair.py /www/wwwroot/mysite.com --from-report report.json --url https://mysite.com

# 2) 手动指定文件隔离(可多个,路径相对站点目录或绝对路径都行)
python3 sr-repair.py /www/wwwroot/mysite.com --quarantine wp-content/uploads/shell.php --url https://mysite.com

# 3) 回滚:把某次隔离的文件全部放回原位(并校验 hash)
python3 sr-repair.py --rollback /www/backup/quarantine-20260803-1200/manifest.json

# 4) 任何修改性命令加 --dry-run:只打印计划,不动手
```

常用参数:

- `--url https://你的域名` —— 强烈建议提供,没有它闸门 3(健康回归)无法执行。
- `--force-backup` —— 没找到 24h 内备份时,先自动打包整站再继续(不用手动备份)。
- `--backup-dir 目录` —— 备份放在别的地方/检查别的地方的备份。
- `--quarantine-dir 目录` —— 隔离区根目录(默认 `/www/backup`),每次操作在下面新建 `quarantine-时间戳` 子目录。**隔离区不允许放在站点目录里面。**
- `--reason "说明"` —— 手动隔离时写进 manifest 的原因。

## 退出码(写脚本时用)

| 码 | 含义 |
|---|---|
| 0 | 成功(或无事可做) |
| 1 | 其他错误(如回滚未全部成功) |
| 2 | 参数/环境错误(站点目录不存在、隔离区设在站点内等) |
| 3 | 备份门禁拒绝(没有 24h 内备份,也没加 --force-backup) |
| 4 | 健康回归发现异常,**已自动回滚**,请人工检查 |
| 5 | 执行失败:--force-backup 自动备份失败,或权限不足(目录不可写/文件无法移动) |

**所有拒绝/失败路径退出码都是非 0**,脚本化调用(cron/CI)可以直接靠退出码判断。遇到"权限不足"报错时的解法:用 sudo 重新运行,或检查目录/文件属主(chown/chmod),或用 `--backup-dir` / `--quarantine-dir` 指定当前用户可写的目录。

## 它会不会动我的网站?

**会,但动得有规矩**:它只会把你明确指定(或报告【高危】列出)的文件**移动**到站点外的隔离区,原文件完好保留、随时可回滚;它绝不直接删除任何文件,也绝不碰没点名的文件。而且任何移动之前,必须先过备份门禁;移动之后,必须过健康回归,异常就自动滚回去。

v0.1 明确不做的事:不碰数据库、不改 wp-config.php、不重置任何密码、不重装 WordPress 核心。这些在 V1 正式版规划里。

## 隔离之后干什么

隔离只是"把马圈起来",不是完事:

1. 改全部密码:宝塔后台、WordPress 后台、数据库、FTP / SSH,一个都别漏。
2. 更新:WordPress 核心、全部插件和主题升到最新;不用的插件直接卸载。
3. 找根因:不搞清楚怎么进来的,清完还会再被挂。
4. 加固 + 复查。

完整流程见仓库 runbook:[../runbook](../runbook) · https://github.com/LiuPeng-1024/site-rescue

## 免责

本工具按"已知验证手段下未发现"的标准工作,不构成安全承诺。它会替你守规矩(备份/留证/可回滚),但判断"这个文件到底是不是马"仍需人工确认 —— 报高危后先人工过目再隔离,是最稳的姿势。
