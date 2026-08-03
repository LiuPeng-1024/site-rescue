# sr-report — 深度探查报告生成器(把扫描结果翻译成人话)

一句话:把 sr-scan 生成的 JSON 报告,变成**小白站长看得懂的中文报告** —— 看不懂 `eval($_POST)` 没关系,看完这份报告你知道站怎么了、发现了什么、可能是怎么进来的、接下来怎么办。

帮别人清站时,它也可以直接作为交付物发给客户。

## 三步开跑(宝塔用户)

**前提**:你已经跑过 [sr-scan](../scan/),并用 `--json` 存了报告:

```bash
python3 sr-scan.py /www/wwwroot/mysite.com --url https://mysite.com --json report.json
```

**第 1 步**:宝塔面板 →「终端」,下载本工具:

```bash
curl -o sr-report.py https://raw.githubusercontent.com/LiuPeng-1024/site-rescue/main/report/sr-report.py
```

下载超时就在自己电脑打开该链接另存为,再用宝塔「文件」管理器上传。Python 3.6 以上都能跑,只用标准库。

**第 2 步**:生成报告(屏幕直接看):

```bash
python3 sr-report.py report.json
```

**第 3 步**:想存成文件慢慢看 / 发给客户:

```bash
python3 sr-report.py report.json --out my-report
```

会生成两个文件,内容一样、格式不同:

- `my-report.md` —— Markdown 版,适合发到 GitHub / 知识库 / 支持 md 的笔记软件
- `my-report.txt` —— 纯文本版,适合直接贴进微信 / 邮件

## 报告里有什么(五段结构)

1. **你的站怎么了** —— 一句话结论 + 严重度盘点(高危 N 条 / 可疑 N 条)。
2. **发现了什么** —— 每条命中都配大白话解释:这是什么马、为什么危险。比如"eval 一句话木马""goto 混淆壳""uploads 藏 PHP""赌博 cloaking 双面页""REST 泄露用户名"等,不用懂代码也能看懂严重性。
3. **可能是怎么进来的** —— 基于命中的推断:漏洞插件迹象 / 弱密码迹象 / 残留安装包等。**明确标注"推断",不打包票** —— 真根因要查日志。
4. **接下来怎么办** —— 按严重度给步骤:先备份 → 隔离(可配合 [sr-repair](../repair/) 三闸门)→ 改密码 → 更新 → 找根因 → 加固 → 复查,每步链到仓库 runbook 对应章节。
5. **承诺边界** —— "已知手段下未发现 ≠ 绝对干净";"报了高危 ≠ 100% 是马"。

## 它会不会动我的网站?

不会。sr-report 只读那份 JSON 报告,输出两个报告文件 —— 和你的网站目录没有任何关系。

## 免责

报告内容基于 sr-scan 的已知特征码与检查项,是"已知手段下的结论",不构成安全承诺。
