#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sr-report.py — 深度探查报告生成器(把 sr-scan 的 JSON 报告翻译成人话)

定位: 给小白站长看的报告 —— 看不懂"eval($_POST)"没关系,
看完这份报告知道"站怎么了、发现了什么、可能是怎么进来的、接下来怎么办"。
帮清场景也可直接作为交付物。

用法:
  python3 sr-report.py report.json                  # 纯文本版直接打印到屏幕
  python3 sr-report.py report.json --out my-report  # 生成 my-report.md 和 my-report.txt 两个文件

设计原则(与 sr-scan / sr-repair 相同): 只用 Python 标准库,兼容 Python 3.6+,中文输出。
退出码: 0 成功 / 2 参数或报告文件错误。
"""

import argparse
import json
import os
import re
import sys

TOOL_VERSION = "0.1.1"
REPO_URL = "https://github.com/LiuPeng-1024/site-rescue"
RUNBOOK_URL = REPO_URL + "/tree/main/runbook"


# ---------------------------------------------------------------------------
# 命中原因 → 人话解释映射表
# 每条: (匹配正则, 这是什么(一句话), 为什么危险(大白话))
# ---------------------------------------------------------------------------

EXPLAIN_RULES = [
    (r'eval 直接执行外部输入',
     u'一句话木马',
     u'这是最典型也最危险的木马:文件里有一行代码,会把黑客通过网络发来的内容直接当成程序指令执行。'
     u'黑客只要发一个请求,就能在你的服务器上读数据、改页面、传更多木马——等于把服务器的钥匙交给了对方。'),

    (r'assert 直接执行外部输入',
     u'一句话木马(变体)',
     u'和 eval 一句话木马是同一种东西,只是换了个函数名躲避查杀,危险程度完全一样。'),

    (r'goto 混淆',
     u'goto 混淆壳',
     u'正常的网站程序几乎不会用 goto 跳转语句。这个文件里 goto 遍地都是,是黑客故意把代码打乱成'
     u'"迷宫",让人看不懂里面藏了什么——木马就藏在乱跳代码的尽头。真实案例里这种文件能有 160KB,全是迷宫。'),

    (r'uploads 目录下出现 PHP',
     u'图片目录藏马',
     u'uploads 目录是放图片和附件的,正常情况下一个 PHP 文件都不该有。这里出现 PHP,'
     u'基本可以断定是黑客上传的后门,而且它可以通过浏览器网址直接访问执行。'),

    (r'languages 目录下出现非翻译类 PHP',
     u'翻译目录伪装',
     u'languages 目录正常只放 .po/.mo 翻译文件。黑客把木马放进这里,'
     u'是因为路径看起来像系统文件,人工翻目录时容易一眼放过。'),

    (r'base64_decode 与 eval/assert',
     u'base64 藏马',
     u'木马代码先编码成 base64 乱码躲避特征查杀,运行时再解码执行。'
     u'正常插件几乎不会用这种写法,命中基本就是马。'),

    (r'命令执行函数',
     u'命令执行后门',
     u'这个文件能把网页请求里的参数直接当成服务器命令执行,等于黑客在你服务器上开了一个远程命令行:'
     u'删库、拖数据、种挖矿程序都能干。'),

    (r'preg_replace 使用 /e',
     u'废弃语法藏执行点',
     u'preg_replace 的 /e 修饰符会把替换结果当 PHP 代码执行,因为太危险,'
     u'PHP 官方 2013 年就废除了它。现在还在这么写的,基本只有木马。'),

    (r'create_function',
     u'动态函数藏马',
     u'create_function 能把字符串变成可执行函数,常被木马用来动态拼接执行代码。'
     u'这个函数 PHP 官方同样已经废弃。'),

    (r'超长单行',
     u'压缩混淆代码',
     u'正常代码一行最多几百个字符;这个文件有一行长达几千字符,'
     u'是把大段代码压缩成一行来藏恶意内容,是混淆木马的典型长相。'),

    (r'文件名像随机字符串',
     u'随机文件名',
     u'正常插件/主题的文件都有正经名字(比如 functions.php)。随机字符串一样的文件名,'
     u'是黑客上传木马时自动生成的,为的是不容易被搜到、不和正常文件撞名。'),

    (r'泄露用户名',
     u'登录用户名泄露',
     u'网站的 REST 接口把登录用户名直接公开了,任何人都能拿到。黑客拿到用户名后就只差密码——'
     u'如果密码简单,被爆破只是时间问题。'),

    (r'cloaking',
     u'双面页面(cloaking)',
     u'你的网站在玩"变脸":正常访客看到的是你的内容,百度/谷歌的爬虫看到的却是赌博广告。'
     u'结果是搜索结果里你的站变成赌博站、排名和流量被劫持,而你自己访问时一切正常,很难察觉。'),

    (r'核心文件校验失败',
     u'WordPress 核心文件被篡改',
     u'WordPress 官方发布的文件被改动过。官方文件里不会自己长出新代码,被改基本意味着被植入了恶意内容。'),

    (r'git 版本库',
     u'源码仓库暴露',
     u'网站根目录下的 .git 目录能被直接访问,任何人都可以把你的全部源码'
     u'(包括历史版本里的密码和配置)打包下载。'),

    (r'debug\.log',
     u'调试日志暴露',
     u'debug.log 谁都能下载,里面记录着服务器路径、数据库报错等信息,'
     u'是黑客摸清你网站底细的现成情报。'),

    (r'数据库导出',
     u'数据库导出文件暴露',
     u'这是整站数据库的导出文件,放在网站目录里等于把全部数据(文章、用户、密码散列)公开提供下载。'),

    (r'wp-config\.php\.bak',
     u'配置备份暴露',
     u'这个备份文件里有数据库账号密码的明文。黑客下载它,就等于拿到了你的整个数据库。'),

    (r'Duplicator|installer',
     u'搬家工具残留',
     u'这是用 Duplicator 插件搬家后忘了删除的安装脚本。黑客访问它,'
     u'可以按照里面的配置重建甚至接管你的网站。'),

    (r'压缩包残留',
     u'整站压缩包暴露',
     u'放在网站根目录的压缩包谁都能下载,等于整站源码(可能含配置文件和数据库密码)被打包送人。'),

    (r'最近 \d+ 天内被修改',
     u'最近被改动过',
     u'这个文件最近有修改记录。如果是你或你的团队改的,没问题;如果不是,就要追问一句——那是谁改的?'),
]

FALLBACK_TITLE = u'危险特征命中'
FALLBACK_TEXT = (u'扫描器在这里命中了已知危险特征(具体见下面的扫描原话)。'
                 u'这类特征在正常 WordPress 文件里极少出现,建议先隔离,再人工打开确认。')

# 缓存编译后的正则
_COMPILED_RULES = [(re.compile(p, re.I), t, d) for p, t, d in EXPLAIN_RULES]

# 超长单行"可疑级单独命中"的平静版解释(sr-scan v1.1 起单独命中降级为可疑,
# 字体/图标/翻译类数据文件也有超长行,不能再套上面"混淆木马典型长相"的高危措辞;
# 与恶意特征共现的高危级命中仍走 EXPLAIN_RULES 里的严厉版)
LONG_LINE_SUS_TITLE = u'超长数据行'
LONG_LINE_SUS_TEXT = (u'这个文件里有一行特别长,但没有发现其他可疑特征。'
                      u'这种多半是字体、图标、翻译类的数据文件,天生就长这样。'
                      u'确认一下它是不是你装的插件/主题自带的文件即可。')


def explain(reason, level=u''):
    """命中原因 + 严重度(u'高危'/u'可疑') → (标题, 人话解释)"""
    for pattern, title, detail in _COMPILED_RULES:
        if pattern.search(reason):
            # 超长单行按严重度+原因文本分级:可疑级且未见共现 → 平静版
            if (pattern.pattern == r'超长单行' and level == u'可疑'
                    and u'共现' not in reason):
                return LONG_LINE_SUS_TITLE, LONG_LINE_SUS_TEXT
            return title, detail
    return FALLBACK_TITLE, FALLBACK_TEXT


# ---------------------------------------------------------------------------
# 第三段: 可能是怎么进来的(基于命中的推断)
# ---------------------------------------------------------------------------

def infer_clues(data):
    highs = data.get('high', [])
    sus = data.get('suspicious', [])
    all_reasons = u' '.join(e.get('reason', '') for e in highs + sus)
    paths = [e.get('path', '') for e in highs + sus if e.get('path')]

    clues = []
    if re.search(r'Duplicator|installer|数据库导出|压缩包|版本库|配置备份', all_reasons):
        clues.append(u'站上有能被直接下载的残留文件(搬家脚本 / 数据库导出 / 压缩包 / .git / 配置备份)。'
                     u'黑客很可能先下载了这些文件,拿到数据库口令或源码,再长驱直入。')
    if u'泄露用户名' in all_reasons:
        clues.append(u'登录用户名已被 REST 接口公开。如果后台密码不够强,黑客可能直接爆破登录后台,再上传木马。')
    if any(p.startswith('wp-content/uploads/') for p in paths):
        clues.append(u'uploads 目录被写进了 PHP 文件。常见原因:某个插件/主题有文件上传漏洞,'
                     u'或者后台已经失陷后被手动上传。')
    # 问题文件是否集中在某个插件/主题目录
    # (只基于高危命中聚类:可疑命中含大量良性数据文件,聚类会误伤合法插件/主题)
    pref = {}
    high_paths = [e.get('path', '') for e in highs if e.get('path')]
    for p in high_paths:
        m = re.match(r'(wp-content/(?:plugins|themes)/[^/]+)/', p)
        if m:
            pref[m.group(1)] = pref.get(m.group(1), 0) + 1
    for k in sorted(pref):
        if pref[k] >= 2:
            clues.append(u'问题文件集中在 %s 目录,这个插件/主题很可能就是入口或重灾区,重点排查。' % k)
    if u'cloaking' in all_reasons.lower():
        clues.append(u'赌博 cloaking 是"进来之后"种下的,不是入口本身;常见入口是漏洞插件或弱密码。')
    if not clues:
        clues.append(u'未发现明确的入侵入口线索,需要查服务器和网站访问日志才能定位'
                     u'(见 runbook 第 5 章《找根因》)。')
    return clues


# ---------------------------------------------------------------------------
# 第四段: 接下来怎么办(按严重度给步骤)
# ---------------------------------------------------------------------------

def build_steps(n_high, n_sus):
    if n_high:
        return [
            u'第 1 步 备份(最重要,别跳过):宝塔面板 →「网站」备份站点 +「数据库」备份。'
            u'见 runbook《02-备份规矩》。',
            u'第 2 步 隔离高危文件:把它们移到网站目录之外 —— 不要直接删除,留证才能查根因。'
            u'可用本仓库 sr-repair.py 自动隔离(备份门禁 / 只移不删 / 异常自动回滚三道闸门保护),'
            u'或按 runbook《04-清理-隔离与删除》手动操作。',
            u'第 3 步 改密码:宝塔后台、WordPress 后台、数据库、FTP / SSH,全部换掉,一个都别漏。',
            u'第 4 步 更新:WordPress 核心、全部插件和主题升到最新版;不用的插件直接卸载。',
            u'第 5 步 找根因:不搞清楚"是怎么进来的",清完还会再被挂。见 runbook《05-根因定位》。',
            u'第 6 步 加固:wp-config.php 加 DISALLOW_FILE_EDIT、REST 接口收口等,见 runbook《06-加固》。',
            u'第 7 步 复查:按 runbook《07-复查验证》过一遍收工检查,并观察一段时间防复发。',
        ]
    if n_sus:
        return [
            u'第 1 步 逐条核对上面的可疑项:是你自己/团队改的就放心,不是就按高危处理。',
            u'第 2 步 先备份,再清理确认无用的残留文件(debug.log / .sql / 压缩包 / 搬家脚本)。',
            u'第 3 步 按 runbook《06-加固》把加固项补齐。',
            u'第 4 步 过几天再扫一次,确认没有新变化。',
        ]
    return [
        u'第 1 步 保持现状的好习惯:WordPress 核心、插件、主题及时更新。',
        u'第 2 步 按 runbook《06-加固》检查加固项是否齐全。',
        u'第 3 步 定期重扫:每个月跑一次 sr-scan,或在网站出现排名掉/跳转/收录异常词时立刻扫。',
    ]


# ---------------------------------------------------------------------------
# 报告组装(区块结构,Markdown / 纯文本 双渲染)
# ---------------------------------------------------------------------------

def build_blocks(data):
    B = []
    summary = data.get('summary', {})
    n_high = summary.get('high', len(data.get('high', [])))
    n_sus = summary.get('suspicious', len(data.get('suspicious', [])))
    n_notice = summary.get('notices', len(data.get('notices', [])))
    n_passed = summary.get('passed', len(data.get('passed', [])))
    stats = data.get('stats', {})

    B.append(('h1', u'网站急救 · 深度探查报告'))
    meta = [u'站点目录: %s' % data.get('target', u'(未知)')]
    meta.append(u'站点 URL: %s' % (data.get('url') or u'(未提供)'))
    meta.append(u'扫描时间: %s' % data.get('generated_at', u'(未知)'))
    meta.append(u'扫描工具: sr-scan v%s(遍历 %s 个文件,其中 PHP %s 个)'
                % (data.get('version', '?'), stats.get('files', '?'), stats.get('php', '?')))
    for line in meta:
        B.append(('p', line))

    # ---- 一、你的站怎么了 ----
    B.append(('h2', u'一、你的站怎么了'))
    if n_high:
        B.append(('p', u'你的站基本确定被黑了:发现 %d 条高危痕迹(另有 %d 条可疑)。'
                  u'别慌,按第四部分的步骤来,能救。' % (n_high, n_sus)))
    elif n_sus:
        B.append(('p', u'没有发现确凿的木马,但有 %d 条可疑痕迹需要你逐条人工核对。' % n_sus))
    else:
        B.append(('p', u'在已知检查手段范围内,没有发现被黑痕迹。'))
    B.append(('p', u'严重度盘点: 高危 %d 条 / 可疑 %d 条 / 提醒 %d 条 / 通过 %d 项。'
              % (n_high, n_sus, n_notice, n_passed)))

    # ---- 二、发现了什么 ----
    B.append(('h2', u'二、发现了什么'))
    highs = data.get('high', [])
    sus = data.get('suspicious', [])
    if highs:
        B.append(('p', u'以下是基本可以确定的危险痕迹,每条都配了大白话解释:'))
        for i, e in enumerate(highs, 1):
            title, detail = explain(e.get('reason', ''), level=u'高危')
            B.append(('finding', {
                'index': i, 'entry': e, 'level': u'高危',
                'title': title, 'detail': detail}))
    if sus:
        B.append(('p', u'以下是可疑痕迹 —— 不一定是坏事,但需要你确认:'))
        for i, e in enumerate(sus, 1):
            title, detail = explain(e.get('reason', ''), level=u'可疑')
            B.append(('finding', {
                'index': i, 'entry': e, 'level': u'可疑',
                'title': title, 'detail': detail}))
    if not highs and not sus:
        B.append(('p', u'本次没有发现高危或可疑项。'))

    # ---- 三、可能是怎么进来的 ----
    B.append(('h2', u'三、可能是怎么进来的'))
    B.append(('p', u'以下是根据发现内容做出的推断(标注"推断",方向参考,不打包票):'))
    for c in infer_clues(data):
        B.append(('li', c + u'(推断)'))

    # ---- 四、接下来怎么办 ----
    B.append(('h2', u'四、接下来怎么办'))
    for s in build_steps(n_high, n_sus):
        B.append(('p', s))
    B.append(('p', u'runbook 全文: %s' % RUNBOOK_URL))

    # ---- 五、承诺边界 ----
    B.append(('h2', u'五、承诺边界'))
    B.append(('li', u'这份报告基于 sr-scan 的已知特征码与检查项,是"已知手段下的结论"。'))
    B.append(('li', u'报了高危 ≠ 100% 是马:特征码可能误伤个别写法怪异的正常文件,隔离后请人工过目再最终处置。'))
    B.append(('li', u'没报高危 ≠ 绝对干净:新型或定制木马可能不在特征库里;'
              u'网站仍有异常(排名掉、跳转、收录赌博词)时,请人工排查或到仓库找我们。'))
    B.append(('li', u'我们不承诺"100% 查清",只保证"已知手段下查清、修稳"。'))
    B.append(('p', u'—— 由 sr-report v%s 生成 · %s' % (TOOL_VERSION, REPO_URL)))
    return B


def _finding_loc(entry):
    loc = entry.get('path', u'(网络/全站)')
    if entry.get('line') is not None:
        loc = u'%s:%s' % (loc, entry['line'])
    return loc


def render_md(blocks):
    lines = []
    for kind, payload in blocks:
        if kind == 'h1':
            lines += [u'# ' + payload, u'']
        elif kind == 'h2':
            lines += [u'## ' + payload, u'']
        elif kind == 'p':
            lines += [payload, u'']
        elif kind == 'li':
            lines.append(u'- ' + payload)
        elif kind == 'finding':
            lines.append(u'- **%s** `%s` —— %s'
                         % (payload['level'], _finding_loc(payload['entry']), payload['title']))
            lines.append(u'  - 人话: %s' % payload['detail'])
            lines.append(u'  - 扫描原话: %s' % payload['entry'].get('reason', u''))
    return u'\n'.join(lines).rstrip() + u'\n'


def render_txt(blocks):
    lines = []
    for kind, payload in blocks:
        if kind == 'h1':
            lines += [u'=' * 60, payload, u'=' * 60, u'']
        elif kind == 'h2':
            lines += [u'', u'【%s】' % payload, u'']
        elif kind == 'p':
            lines.append(payload)
        elif kind == 'li':
            lines.append(u'  - ' + payload)
        elif kind == 'finding':
            lines.append(u'  %d. [%s] %s —— %s'
                         % (payload['index'], payload['level'],
                            _finding_loc(payload['entry']), payload['title']))
            lines.append(u'       人话: %s' % payload['detail'])
            lines.append(u'       扫描原话: %s' % payload['entry'].get('reason', u''))
    return u'\n'.join(lines).rstrip() + u'\n'


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description=u'把 sr-scan 的 JSON 报告翻译成小白站长看得懂的人话报告(Markdown + 纯文本)')
    parser.add_argument('report_json', help=u'sr-scan 生成的 JSON 报告路径(--json 产物)')
    parser.add_argument('--out', dest='out_prefix', default=None,
                        help=u'输出文件前缀: 生成 <前缀>.md 和 <前缀>.txt;不给则把纯文本版打印到屏幕')
    args = parser.parse_args(argv)

    try:
        with open(args.report_json, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (IOError, OSError, ValueError) as e:
        sys.stderr.write(u'错误: 无法读取报告文件: %s(%s)\n' % (args.report_json, e))
        return 2

    if data.get('tool') != 'sr-scan':
        sys.stderr.write(u'警告: 该文件可能不是 sr-scan 报告(tool=%s),仍将尝试生成。\n'
                         % data.get('tool'))

    blocks = build_blocks(data)
    md = render_md(blocks)
    txt = render_txt(blocks)

    if not args.out_prefix:
        sys.stdout.write(txt)
        sys.stdout.write(u'\n(提示: 加 --out 前缀 可同时生成 Markdown 和纯文本两个文件)\n')
        return 0

    md_path = args.out_prefix + '.md'
    txt_path = args.out_prefix + '.txt'
    try:
        out_dir = os.path.dirname(os.path.abspath(args.out_prefix))
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir)
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(md)
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(txt)
    except (IOError, OSError) as e:
        sys.stderr.write(u'错误: 报告写入失败: %s\n' % e)
        return 2

    print(u'已生成:')
    print(u'  Markdown 版: %s' % md_path)
    print(u'  纯文本版:   %s' % txt_path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
