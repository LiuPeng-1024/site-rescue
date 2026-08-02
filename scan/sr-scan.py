#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sr-scan.py — 宝塔 + WordPress 网站被黑排查扫描器(只读)

用法:
    python sr-scan.py /www/wwwroot/mysite.com [--url https://mysite.com] [--days 14] [--json report.json]

设计原则:
    1. 只用 Python 标准库,兼容 Python 3.6+(目标机器是小白用户的宝塔服务器,可能什么都没有)
    2. 绝对只读:不修改/删除/移动目标站任何文件,不写目标站目录
       唯一允许的写操作是用户显式指定的 --json 输出路径
    3. 发现任一高危项,退出码为 1,否则为 0(方便 CI/自动化)
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

TOOL_VERSION = "1.0.0"
REPO_URL = "https://github.com/LiuPeng-1024/site-rescue"

# ---------------------------------------------------------------------------
# 特征码(webshell 正则)
# ---------------------------------------------------------------------------

# eval/assert 直接执行外部输入,如 eval($_POST['1']) —— 真实案例
RE_EVAL_INPUT = re.compile(r'eval\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)', re.I)
RE_ASSERT_INPUT = re.compile(r'assert\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)', re.I)

# create_function 可动态生成函数体,是老旧但常见的执行点
RE_CREATE_FUNCTION = re.compile(r'\bcreate_function\s*\(', re.I)

# preg_replace 的 /e 修饰符会把替换结果当 PHP 代码执行(PHP 5.5 起移除,见到即恶意)
# 组1取模式串的定界符(引号内第一个字符),要求闭合定界符后的修饰符中含 e
RE_PREG_E = re.compile(
    r'preg_replace\s*\(\s*[\'"](.).{0,300}?\1[imsxADSUXJu]*e[imsxADSUXJu]*[\'"]\s*,',
    re.I)

# 同文件共现类检查(按整个文件内容判断)
RE_B64_DECODE = re.compile(r'\bbase64_decode\s*\(', re.I)
RE_EVAL_ANY = re.compile(r'\b(?:eval|assert)\s*\(', re.I)
RE_DANGER_FUNC = re.compile(r'\b(?:shell_exec|system|passthru|popen|proc_open)\s*\(', re.I)
RE_INPUT_VAR = re.compile(r'\$_(?:GET|POST|REQUEST|COOKIE)', re.I)

# goto 混淆:统计 goto 语句出现次数(真实案例:161KB 的 wp-content/languages/zxvsg.php)
RE_GOTO = re.compile(r'\bgoto\s+[A-Za-z_]', re.I)
GOTO_THRESHOLD = 5

# 超长单行(混淆代码典型特征)
LONG_LINE_THRESHOLD = 2000

# 随机文件名判断:全小写字母+数字、长度 >= 8,且元音占比极低或连续辅音很长
RE_RANDOM_NAME = re.compile(r'^[a-z0-9]+$')
RANDOM_NAME_MIN_LEN = 8

# wp-content/languages 下合法的翻译类文件名,如 zh_CN.php、en_GB.php
RE_LOCALE_PHP = re.compile(r'^[a-z]{2,3}_[A-Z]{2,3}\.php$')

# 赌博关键词(cloaking 初检用)
GAMBLING_KEYWORDS = [u'赌博', u'棋牌', u'博彩', u'威尼斯人', u'百家乐', u'彩票', u'开元']

NORMAL_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
             '(KHTML, like Gecko) Chrome/124.0 Safari/537.36 sr-scan/' + TOOL_VERSION)
GOOGLEBOT_UA = ('Mozilla/5.0 (compatible; Googlebot/2.1; '
                '+http://www.google.com/bot.html)')

HTTP_TIMEOUT = 15


# ---------------------------------------------------------------------------
# 结果收集
# ---------------------------------------------------------------------------

class Report(object):
    """分级收集检查结果:high 高危 / suspicious 可疑 / notices 提醒 / passed 通过项"""

    def __init__(self):
        self.high = []
        self.suspicious = []
        self.notices = []
        self.passed = []

    @staticmethod
    def _entry(path, reason, line):
        e = {}
        if path is not None:
            e['path'] = path
        if line is not None:
            e['line'] = line
        e['reason'] = reason
        return e

    def add_high(self, path=None, reason='', line=None):
        self.high.append(self._entry(path, reason, line))

    def add_suspicious(self, path=None, reason='', line=None):
        self.suspicious.append(self._entry(path, reason, line))

    def add_notice(self, reason=''):
        self.notices.append({'reason': reason})

    def add_passed(self, check='', detail=''):
        self.passed.append({'check': check, 'detail': detail})


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def read_text(path):
    """以二进制读入再按 utf-8 容错解码,避免坏编码文件让扫描中断"""
    with open(path, 'rb') as f:
        data = f.read()
    return data.decode('utf-8', 'ignore')


def rel_display(path, root):
    """文件相对路径,统一用 / 分隔,跨平台输出一致"""
    rel = os.path.relpath(path, root)
    return rel.replace(os.sep, '/')


def fmt_time(ts):
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))


def looks_random_name(name):
    """判断文件名(不含扩展名)是否像随机字符串。
    启发式:全小写字母/数字、长度 >= 8,且元音占比 < 25% 或最长连续辅音 >= 6。
    保守取向,宁可漏判不要误伤 functions.php、shortcodes.php 这类正常文件。
    """
    if len(name) < RANDOM_NAME_MIN_LEN or not RE_RANDOM_NAME.match(name):
        return False
    vowels = sum(1 for c in name if c in 'aeiou')
    if vowels * 4 < len(name):  # 元音占比 < 25%
        return True
    run = 0
    max_run = 0
    for c in name:
        if c not in 'aeiou':
            run += 1
            max_run = max(max_run, run)
        else:
            run = 0
    return max_run >= 6


# ---------------------------------------------------------------------------
# 本地文件检查
# ---------------------------------------------------------------------------

def scan_php_file(path, rel, report):
    """对单个 PHP 文件做特征码扫描,命中写入 report.high"""
    try:
        content = read_text(path)
    except (IOError, OSError) as e:
        report.add_notice(u'文件读取失败,已跳过: %s (%s)' % (rel, e))
        return

    lines = content.splitlines()

    # --- 逐行检查:eval/assert 执行外部输入、create_function、preg_replace /e、超长行 ---
    hit_eval = hit_assert = hit_cf = hit_prege = 0
    long_lines = []
    for idx, line in enumerate(lines, 1):
        if hit_eval < 5 and RE_EVAL_INPUT.search(line):
            report.add_high(rel, u'eval 直接执行外部输入(eval($_POST/$_GET 等),典型一句话木马', idx)
            hit_eval += 1
        if hit_assert < 5 and RE_ASSERT_INPUT.search(line):
            report.add_high(rel, u'assert 直接执行外部输入,典型一句话木马变体', idx)
            hit_assert += 1
        if hit_cf < 5 and RE_CREATE_FUNCTION.search(line):
            report.add_high(rel, u'使用 create_function 动态创建函数(常见代码执行手法)', idx)
            hit_cf += 1
        if hit_prege < 5 and RE_PREG_E.search(line):
            report.add_high(rel, u'preg_replace 使用 /e 修饰符(替换结果会被当 PHP 代码执行)', idx)
            hit_prege += 1
        if len(line) > LONG_LINE_THRESHOLD:
            long_lines.append((idx, len(line)))

    if long_lines:
        first = long_lines[0]
        report.add_high(
            rel,
            u'存在超长单行(第 %d 行 %d 字符,共 %d 行超过 %d 字符),混淆代码典型特征'
            % (first[0], first[1], len(long_lines), LONG_LINE_THRESHOLD),
            first[0])

    # --- 整文件共现检查 ---
    if RE_B64_DECODE.search(content) and RE_EVAL_ANY.search(content):
        report.add_high(rel, u'base64_decode 与 eval/assert 同文件共现(base64 藏马典型组合)')

    m_danger = RE_DANGER_FUNC.search(content)
    if m_danger and RE_INPUT_VAR.search(content):
        report.add_high(rel, u'命令执行函数 %s 与外部输入 $_GET/$_POST 同文件共现(疑似命令执行后门)'
                        % m_danger.group(0).rstrip('('))

    goto_count = len(RE_GOTO.findall(content))
    if goto_count >= GOTO_THRESHOLD:
        report.add_high(rel, u'goto 混淆:文件内 goto 语句 %d 处(>= %d),正常代码几乎不用 goto'
                        % (goto_count, GOTO_THRESHOLD))


def scan_site(root, days, report):
    """遍历站点目录,执行全部本地检查"""
    php_files = []          # (abs_path, rel, mtime)
    leftover_hits = []      # (rel, reason)
    has_uploads_php_rule = {'hit': False}   # 用 dict 包一层,兼容 3.6 的闭包写法
    stats = {'php': 0, 'files': 0}

    for dirpath, dirnames, filenames in os.walk(root):
        # 不进入版本库目录,避免无意义遍历(.git 暴露单独检测)
        if '.git' in dirnames:
            dirnames.remove('.git')
        dirnames.sort()
        for name in sorted(filenames):
            stats['files'] += 1
            fpath = os.path.join(dirpath, name)
            rel = rel_display(fpath, root)
            lname = name.lower()

            # --- 危险残留文件(与扩展名无关,遍历到就判断) ---
            if lname == 'debug.log':
                leftover_hits.append((rel, u'debug.log 调试日志暴露,可能泄露路径/数据库错误等敏感信息'))
            elif lname.endswith('.sql'):
                leftover_hits.append((rel, u'.sql 数据库导出文件残留,可能被直接下载'))
            elif lname == 'wp-config.php.bak':
                leftover_hits.append((rel, u'wp-config.php.bak 配置备份暴露,数据库口令可能泄露'))
            elif lname == 'installer.php' or lname.startswith('dup-installer'):
                leftover_hits.append((rel, u'Duplicator 搬家工具残留(installer 可被利用重建站点)'))
            elif '/' not in rel and (lname.endswith('.zip') or lname.endswith('.tar.gz')):
                leftover_hits.append((rel, u'根目录压缩包残留,可能整站被打包下载'))

            if not lname.endswith('.php'):
                continue

            stats['php'] += 1
            try:
                mtime = os.path.getmtime(fpath)
            except (IOError, OSError):
                mtime = 0
            php_files.append((fpath, rel, mtime))

            # --- 错误位置的 PHP ---
            if rel.startswith('wp-content/uploads/'):
                has_uploads_php_rule['hit'] = True
                report.add_high(rel, u'uploads 目录下出现 PHP 文件(uploads 本应只有图片等媒体文件)')
            elif rel.startswith('wp-content/languages/') and not RE_LOCALE_PHP.match(name):
                report.add_high(rel, u'languages 目录下出现非翻译类 PHP 文件(该目录正常只有 .po/.mo)')

            # --- 随机文件名 ---
            stem = name[:-4]  # 去掉 .php
            if looks_random_name(stem):
                report.add_high(rel, u'文件名像随机字符串(%s),正常插件/主题不会这样命名' % name)

            # --- webshell 特征码 ---
            scan_php_file(fpath, rel, report)

    # --- .git 暴露(根目录) ---
    if os.path.isdir(os.path.join(root, '.git')):
        report.add_suspicious('.git', u'站点根目录存在 .git 版本库,源码/历史配置可能被打包下载')
    else:
        report.add_passed(u'.git 暴露检查', u'根目录未发现 .git 目录')

    # --- 危险残留 ---
    if leftover_hits:
        for rel, reason in leftover_hits:
            report.add_suspicious(rel, reason)
    else:
        report.add_passed(u'危险残留文件检查', u'未发现 debug.log/.sql/压缩包/Duplicator 残留')

    # --- 最近 N 天被修改的 PHP ---
    cutoff = time.time() - days * 86400
    recent = [(m, r) for (_p, r, m) in php_files if m >= cutoff]
    recent.sort(key=lambda x: x[0], reverse=True)
    high_paths = set(e.get('path') for e in report.high)
    if recent:
        for m, rel in recent[:50]:
            mark = u'(已在高危中列出)' if rel in high_paths else u''
            report.add_suspicious(rel, u'最近 %d 天内被修改(%s)%s,请确认是否本人/团队所为'
                                  % (days, fmt_time(m), mark))
        if len(recent) > 50:
            report.add_notice(u'最近 %d 天内变动的 PHP 共 %d 个,仅列出前 50 个' % (days, len(recent)))
    else:
        report.add_passed(u'最近文件变动检查', u'最近 %d 天内没有 PHP 文件被修改' % days)

    if not has_uploads_php_rule['hit']:
        report.add_passed(u'uploads 目录检查', u'wp-content/uploads 下未发现 PHP 文件')

    return stats


def check_wp_config(root, report):
    """wp-config.php 加固检查"""
    cfg = os.path.join(root, 'wp-config.php')
    if not os.path.isfile(cfg):
        report.add_notice(u'未找到 wp-config.php,请确认传入的是 WordPress 站点根目录')
        return
    try:
        content = read_text(cfg)
    except (IOError, OSError) as e:
        report.add_notice(u'wp-config.php 读取失败: %s' % e)
        return

    if re.search(r"define\s*\(\s*['\"]DISALLOW_FILE_EDIT['\"]\s*,\s*true", content, re.I):
        report.add_passed(u'DISALLOW_FILE_EDIT', u'已禁止后台编辑主题/插件文件')
    else:
        report.add_notice(u'wp-config.php 未定义 DISALLOW_FILE_EDIT,建议加: '
                          u"define('DISALLOW_FILE_EDIT', true); (防止后台被直接改代码)")

    if re.search(r"define\s*\(\s*['\"]DISALLOW_FILE_MODS['\"]\s*,\s*true", content, re.I):
        report.add_passed(u'DISALLOW_FILE_MODS', u'已禁止后台安装/更新插件主题')
    else:
        report.add_notice(u'wp-config.php 未定义 DISALLOW_FILE_MODS,可视需要加: '
                          u"define('DISALLOW_FILE_MODS', true); (注意:加上后后台不能更新插件)")


def check_wp_version(root, report):
    """从 wp-includes/version.php 读取 WordPress 版本"""
    ver_file = os.path.join(root, 'wp-includes', 'version.php')
    if not os.path.isfile(ver_file):
        report.add_notice(u'未找到 wp-includes/version.php,无法确认 WordPress 版本')
        return
    try:
        content = read_text(ver_file)
    except (IOError, OSError) as e:
        report.add_notice(u'version.php 读取失败: %s' % e)
        return
    m = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", content)
    if m:
        report.add_notice(u'当前 WordPress 版本: %s(请到 wordpress.org 核对是否最新,旧版本常有已知漏洞)' % m.group(1))
    else:
        report.add_notice(u'wp-includes/version.php 存在但未解析出版本号')


def check_plugins(root, report):
    """列出已安装插件及 readme.txt 里的 Stable tag"""
    pdir = os.path.join(root, 'wp-content', 'plugins')
    if not os.path.isdir(pdir):
        report.add_notice(u'未找到 wp-content/plugins 目录')
        return
    found = 0
    for name in sorted(os.listdir(pdir)):
        sub = os.path.join(pdir, name)
        if not os.path.isdir(sub):
            continue
        found += 1
        tag = None
        readme = os.path.join(sub, 'readme.txt')
        if os.path.isfile(readme):
            try:
                m = re.search(r'^\s*Stable tag:\s*(\S+)', read_text(readme), re.I | re.M)
                if m:
                    tag = m.group(1)
            except (IOError, OSError):
                pass
        if tag:
            report.add_notice(u'已安装插件: %s(Stable tag: %s)—— 请确认全部为本人安装且已更新到最新版' % (name, tag))
        else:
            report.add_notice(u'已安装插件: %s(版本未知,无 readme.txt Stable tag)—— 请确认是否本人安装' % name)
    if found == 0:
        report.add_notice(u'wp-content/plugins 下没有发现任何插件目录')


# ---------------------------------------------------------------------------
# 网络检查(仅 --url 提供时)
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟随 30x 跳转,便于区分'直接 200 泄露'和'301 到作者归档'"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def http_get(url, ua, follow_redirect=True):
    """发起 GET 请求,返回 (状态码, 响应体文本, Location 头)。
    网络异常时抛出,由调用方决定记录到哪一级。"""
    req = urllib.request.Request(url, headers={'User-Agent': ua})
    opener = urllib.request.build_opener() if follow_redirect else _NO_REDIRECT_OPENER
    try:
        resp = opener.open(req, timeout=HTTP_TIMEOUT)
        body = resp.read(2 * 1024 * 1024).decode('utf-8', 'ignore')
        code = resp.getcode()
        resp.close()
        return code, body, None
    except urllib.error.HTTPError as e:
        # 不跟随跳转时 301 也会走到这里;4xx/5xx 同样
        body = b''
        try:
            body = e.read(512 * 1024)
        except Exception:
            pass
        return e.code, body.decode('utf-8', 'ignore'), e.headers.get('Location')


def check_rest_user_enum(base_url, report, net_detail):
    """REST 用户枚举三种变体:期望 4xx 或 301;200 且含用户名则为高危"""
    variants = [
        ('/wp-json/wp/v2/users', u'REST 接口 /wp-json/wp/v2/users'),
        ('/?rest_route=/wp/v2/users', u'REST 接口 ?rest_route=/wp/v2/users(nginx 拦不住 query 参数,常绕过边界规则)'),
        ('/?author=1', u'作者归档 ?author=1'),
    ]
    results = []
    for suffix, label in variants:
        url = base_url + suffix
        try:
            code, body, location = http_get(url, NORMAL_UA, follow_redirect=False)
        except Exception as e:
            report.add_notice(u'网络检查失败(%s): %s' % (label, e))
            results.append({'check': label, 'status': 'error', 'detail': str(e)})
            continue

        if code == 200:
            usernames = []
            if '"slug"' in body:
                # REST JSON 响应,提取 slug 字段
                usernames = re.findall(r'"slug"\s*:\s*"([^"]+)"', body)
            elif 'author=' in suffix:
                # 作者归档页,尝试从页面里找 /author/xxx 痕迹
                usernames = re.findall(r'/author/([^/"\']+)', body)
            if usernames:
                uniq = sorted(set(usernames))[:10]
                report.add_high(reason=u'%s 返回 200 且泄露用户名: %s(可被用于爆破登录)'
                                % (label, u', '.join(uniq)))
                results.append({'check': label, 'status': 'leak', 'usernames': uniq})
            else:
                report.add_passed(label, u'返回 200 但未发现用户名痕迹')
                results.append({'check': label, 'status': 'ok_no_leak', 'http': code})
        elif code in (301, 302, 303, 307, 308):
            report.add_passed(label, u'返回 %d(未直接返回用户数据)' % code)
            results.append({'check': label, 'status': 'redirect', 'http': code, 'location': location})
        elif 400 <= code < 500:
            report.add_passed(label, u'返回 %d,已拦截' % code)
            results.append({'check': label, 'status': 'blocked', 'http': code})
        else:
            report.add_notice(u'%s 返回非预期状态码 %d,请人工确认' % (label, code))
            results.append({'check': label, 'status': 'unexpected', 'http': code})
    net_detail['rest_user_enum'] = results


def check_cloaking(base_url, report, net_detail):
    """cloaking 初检:普通 UA 与 Googlebot UA 分别抓首页,对比标题/正文长度/赌博关键词"""
    def extract_title(body):
        m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
        return re.sub(r'\s+', ' ', m.group(1)).strip() if m else ''

    def kw_count(body):
        return sum(body.count(k) for k in GAMBLING_KEYWORDS)

    try:
        code_n, body_n, _ = http_get(base_url + '/', NORMAL_UA)
    except Exception as e:
        report.add_notice(u'网络检查失败(普通 UA 抓首页): %s' % e)
        net_detail['cloaking'] = {'status': 'error', 'detail': str(e)}
        return
    try:
        code_g, body_g, _ = http_get(base_url + '/', GOOGLEBOT_UA)
    except Exception as e:
        report.add_notice(u'网络检查失败(Googlebot UA 抓首页): %s' % e)
        net_detail['cloaking'] = {'status': 'error', 'detail': str(e)}
        return

    title_n, title_g = extract_title(body_n), extract_title(body_g)
    len_n, len_g = len(body_n), len(body_g)
    kw_n, kw_g = kw_count(body_n), kw_count(body_g)
    ratio = (float(len_g) / len_n) if len_n else 0.0

    detail = {
        'status': 'checked',
        'normal': {'http': code_n, 'title': title_n, 'body_len': len_n, 'gambling_kw': kw_n},
        'googlebot': {'http': code_g, 'title': title_g, 'body_len': len_g, 'gambling_kw': kw_g},
    }
    net_detail['cloaking'] = detail

    reasons = []
    if kw_g - kw_n >= 2:
        reasons.append(u'Googlebot 看到的页面赌博关键词 %d 处,普通访客 %d 处' % (kw_g, kw_n))
    if title_n != title_g and not (0.5 <= ratio <= 2.0):
        reasons.append(u'标题不同且正文长度差异大(普通 %d 字节 / 蜘蛛 %d 字节)' % (len_n, len_g))

    if reasons:
        report.add_high(reason=u'疑似 cloaking(给搜索引擎看赌博页、给正常访客看正常页): ' + u';'.join(reasons))
        detail['status'] = 'suspect'
    else:
        report.add_passed(u'cloaking 初检',
                          u'两种 UA 抓取结果未见显著差异(标题%s,正文 %d/%d 字节,赌博词 %d/%d)'
                          % (u'相同' if title_n == title_g else u'不同', len_n, len_g, kw_n, kw_g))


def check_wp_cli(root, report, net_detail):
    """服务器上装了 wp-cli 就跑核心文件校验;没装则注明跳过"""
    wp = shutil.which('wp')
    if not wp:
        report.add_notice(u'未检测到 wp-cli,已跳过核心文件完整性校验'
                          u'(可手动执行: wp core verify-checksums --path=%s)' % root)
        net_detail['wp_cli'] = {'status': 'skipped', 'reason': 'wp-cli not found'}
        return
    try:
        proc = subprocess.run(
            [wp, 'core', 'verify-checksums', '--path=' + root],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=120)
        out = proc.stdout or ''
    except Exception as e:
        report.add_notice(u'wp core verify-checksums 执行失败: %s' % e)
        net_detail['wp_cli'] = {'status': 'error', 'detail': str(e)}
        return

    if proc.returncode == 0:
        report.add_passed(u'wp core verify-checksums', u'WordPress 核心文件校验通过')
        net_detail['wp_cli'] = {'status': 'ok'}
    else:
        bad = re.findall(r"File doesn't verify against checksum:\s*(\S+)", out)
        if bad:
            for f in bad[:50]:
                report.add_high(f, u'WordPress 核心文件校验失败(被篡改或非官方版本),wp-cli 报告')
            net_detail['wp_cli'] = {'status': 'fail', 'files': bad[:50]}
        else:
            report.add_notice(u'wp core verify-checksums 返回非 0 但未解析出具体文件,原始输出: %s'
                              % out.strip()[:300])
            net_detail['wp_cli'] = {'status': 'fail', 'raw': out.strip()[:500]}


# ---------------------------------------------------------------------------
# 报告输出
# ---------------------------------------------------------------------------

def print_section(title, items, formatter):
    print(u'【%s】共 %d 项' % (title, len(items)))
    if not items:
        print(u'  (无)')
    for i, it in enumerate(items, 1):
        print(u'  %d. %s' % (i, formatter(it)))
    print(u'')


def _fmt_finding(it):
    loc = it.get('path', u'(网络/全站)')
    if it.get('line') is not None:
        loc = u'%s:%d' % (loc, it['line'])
    return u'%s —— %s' % (loc, it['reason'])


def print_report(report, target, url, days, stats):
    print(u'=' * 60)
    print(u'sr-scan v%s 扫描报告' % TOOL_VERSION)
    print(u'目标目录: %s' % target)
    print(u'站点 URL: %s' % (url if url else u'(未提供,网络检查已跳过)'))
    print(u'最近修改检查窗口: %d 天' % days)
    print(u'共遍历文件 %d 个,其中 PHP %d 个' % (stats['files'], stats['php']))
    print(u'=' * 60)
    print(u'')

    print_section(u'高危', report.high, _fmt_finding)
    print_section(u'可疑', report.suspicious, _fmt_finding)
    print_section(u'提醒', report.notices, lambda it: it['reason'])
    print_section(u'通过项', report.passed,
                  lambda it: u'%s —— %s' % (it['check'], it['detail']) if it.get('detail') else it['check'])

    print(u'===== 下一步建议 =====')
    if report.high:
        print(u'- 发现 %d 个高危项:先完整备份整站文件和数据库,再把高危文件隔离'
              u'(移出 web 目录),不要直接删除——留证才能查根因。' % len(report.high))
    if report.suspicious:
        print(u'- 逐项核对可疑文件:确认是否你本人/团队最近修改或遗留;确认无用后先备份再清理。')
    print(u'- 加固:确认 wp-config.php 已定义 DISALLOW_FILE_EDIT;WordPress 核心与全部插件保持最新;定期更换后台/数据库/FTP 口令。')
    print(u'- 详细处置流程见仓库 runbook: %s' % REPO_URL)
    if not report.high and not report.suspicious:
        print(u'- 本次未发现高危/可疑项。注意:本工具是特征码初筛,不等于深度取证,网站仍有异常时请人工排查。')
    print(u'')


def build_json_report(report, target, url, days, stats, net_detail):
    return {
        'tool': 'sr-scan',
        'version': TOOL_VERSION,
        'target': target,
        'url': url,
        'days': days,
        'generated_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
        'stats': stats,
        'summary': {
            'high': len(report.high),
            'suspicious': len(report.suspicious),
            'notices': len(report.notices),
            'passed': len(report.passed),
        },
        'high': report.high,
        'suspicious': report.suspicious,
        'notices': report.notices,
        'passed': report.passed,
        'network': net_detail,
    }


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description=u'宝塔 + WordPress 网站被黑排查扫描器(只读,标准库实现)')
    parser.add_argument('site_dir', help=u'WordPress 站点根目录,如 /www/wwwroot/mysite.com')
    parser.add_argument('--url', default=None,
                        help=u'站点 URL,提供后启用网络检查(REST 枚举 + cloaking 初检)')
    parser.add_argument('--days', type=int, default=14,
                        help=u'最近修改文件检查的时间窗口(天),默认 14')
    parser.add_argument('--json', dest='json_path', default=None,
                        help=u'把结构化报告写到指定 JSON 文件路径')
    args = parser.parse_args(argv)

    root = os.path.abspath(args.site_dir)
    if not os.path.isdir(root):
        sys.stderr.write(u'错误: 目录不存在或不是目录: %s\n' % args.site_dir)
        return 2

    report = Report()
    stats = scan_site(root, args.days, report)
    check_wp_config(root, report)
    check_wp_version(root, report)
    check_plugins(root, report)

    net_detail = None
    if args.url:
        base = args.url.rstrip('/')
        net_detail = {}
        check_rest_user_enum(base, report, net_detail)
        check_cloaking(base, report, net_detail)
        check_wp_cli(root, report, net_detail)
    else:
        report.add_notice(u'未提供 --url,网络检查(REST 用户枚举/cloaking 初检/wp-cli 校验)已整体跳过')

    print_report(report, root, args.url, args.days, stats)

    if args.json_path:
        data = build_json_report(report, root, args.url, args.days, stats, net_detail)
        try:
            jdir = os.path.dirname(os.path.abspath(args.json_path))
            if jdir and not os.path.isdir(jdir):
                os.makedirs(jdir)
            with open(args.json_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(u'JSON 报告已写入: %s' % args.json_path)
        except (IOError, OSError) as e:
            sys.stderr.write(u'错误: JSON 报告写入失败: %s\n' % e)

    return 1 if report.high else 0


if __name__ == '__main__':
    sys.exit(main())
