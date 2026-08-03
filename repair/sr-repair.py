#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sr-repair.py — 宝塔 + WordPress 被黑站修复安全骨架(v0.1,三闸门)

定位: 这不是全自动修复引擎,而是"安全执行修复动作的地基"。
现在的半自动帮清、未来的自动修复引擎,都建立在这三道代码级强制的闸门之上
(是代码里的硬校验,不是提示语):

  闸门1 备份门禁: 任何修改性操作前,检查 24 小时内是否存在有效备份
        (检查顺序: --backup-dir 指定目录 → 宝塔默认 /www/backup)。
        没有备份就拒绝执行;加 --force-backup 则先自动打包整站再继续。
  闸门2 隔离不删: 所有"清除"动作一律移动到站点之外的 quarantine-时间戳 目录,
        并写 manifest.json(原路径/隔离路径/时间/命中原因/操作前 hash)留证。
        全代码没有任何"直接删除站点文件"的调用,欢迎 grep 源码自证。
  闸门3 健康回归: 操作前抓取关键 URL 快照(HTTP 状态 + 内容长度 + 关键标记),
        操作后复抓对比;异常(状态码变 5xx、长度偏差 > 50%、关键标记消失)
        自动按 manifest 回滚全部已隔离文件并报告。

用法:
  python3 sr-repair.py /www/wwwroot/mysite.com --from-report report.json --url https://mysite.com
  python3 sr-repair.py /www/wwwroot/mysite.com --quarantine wp-content/uploads/shell.php --url https://mysite.com
  python3 sr-repair.py --rollback /www/backup/quarantine-20260803-1200/manifest.json
  任何修改性命令加 --dry-run: 只打印将做什么,不动手

退出码: 0 成功 / 1 一般错误 / 2 参数或环境错误 / 3 备份门禁拒绝 / 4 健康回归异常(已自动回滚)

设计原则(与 sr-scan 相同): 只用 Python 标准库,兼容 Python 3.6+,中文输出。
v0.1 暂不做: 数据库操作、wp-config 修改、密码重置、核心重装(V1 正式版的事)。
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import time
import urllib.error
import urllib.request

TOOL_VERSION = "0.1.0"
REPO_URL = "https://github.com/LiuPeng-1024/site-rescue"
RUNBOOK_URL = REPO_URL + "/tree/main/runbook"

BACKUP_MAX_AGE = 24 * 3600            # 备份有效期: 24 小时
DEFAULT_BACKUP_ROOT = '/www/backup'   # 宝塔默认备份目录
HTTP_TIMEOUT = 15
LEN_TOLERANCE = 0.5                   # 健康回归: 内容长度偏差阈值

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/124.0 Safari/537.36 sr-repair/' + TOOL_VERSION)


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def fmt_time(ts):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))


def now_str():
    return fmt_time(time.time())


def rel_display(path, root):
    """文件相对路径,统一用 / 分隔,跨平台输出一致"""
    rel = os.path.relpath(path, root)
    return rel.replace(os.sep, '/')


def sha256_file(path):
    """流式计算文件 sha256,用于操作前留证和回滚后校验"""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def resolve_site_file(site_dir, given):
    """把报告/用户给的路径解析成站点内绝对路径。
    越界(逃出站点目录)返回 None —— 本工具只允许动站点目录内的文件。"""
    if os.path.isabs(given):
        ap = os.path.abspath(given)
    else:
        ap = os.path.abspath(os.path.join(site_dir, given))
    prefix = site_dir.rstrip(os.sep) + os.sep
    if not ap.startswith(prefix):
        return None
    return ap


# ---------------------------------------------------------------------------
# 闸门 1: 备份门禁
# ---------------------------------------------------------------------------

def find_recent_backup(dirs):
    """在给定目录里找 24 小时内生成的非空文件,返回最新一个 (path, mtime)。
    跳过 quarantine-* 目录: 那里面是我们自己的隔离留证,不是备份。"""
    now = time.time()
    best = None
    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        for dirpath, dirnames, filenames in os.walk(d):
            dirnames[:] = [x for x in dirnames if not x.startswith('quarantine-')]
            for name in filenames:
                fp = os.path.join(dirpath, name)
                try:
                    st = os.stat(fp)
                except OSError:
                    continue
                if st.st_size <= 0:
                    continue
                if now - st.st_mtime <= BACKUP_MAX_AGE:
                    if best is None or st.st_mtime > best[1]:
                        best = (fp, st.st_mtime)
    return best


def make_backup(site_dir, dest_dir):
    """--force-backup: 把整站打成 tar.gz 放进备份目录,并验证产物存在且非空"""
    if not os.path.isdir(dest_dir):
        os.makedirs(dest_dir)
    name = 'sr-backup-%s.tar.gz' % time.strftime('%Y%m%d-%H%M%S')
    path = os.path.join(dest_dir, name)
    with tarfile.open(path, 'w:gz') as tar:
        tar.add(site_dir, arcname=os.path.basename(site_dir.rstrip(os.sep)))
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        raise IOError(u'备份文件生成后校验失败(不存在或为空)')
    return path


def gate_backup(args, site_dir):
    """闸门 1。返回 True 放行,False 拒绝。"""
    print(u'===== 闸门 1/3: 备份门禁 =====')
    search_dirs = []
    if args.backup_dir:
        search_dirs.append(args.backup_dir)
    search_dirs.append(DEFAULT_BACKUP_ROOT)

    found = find_recent_backup(search_dirs)
    if found:
        print(u'  [通过] 发现 24 小时内的备份: %s(%s,%.1f MB)'
              % (found[0], fmt_time(found[1]),
                 os.path.getsize(found[0]) / 1048576.0))
        print(u'')
        return True

    print(u'  [未通过] 以下位置均未发现 24 小时内的备份:')
    for d in search_dirs:
        mark = u'' if os.path.isdir(d) else u'(目录不存在)'
        print(u'    - %s %s' % (d, mark))

    if not args.force_backup:
        print(u'')
        print(u'  ★ 拒绝执行: 先备份,再动手 —— 误删比木马更可怕。')
        print(u'    两种解法(任选其一):')
        print(u'    1) 宝塔面板 →「网站」备份站点 +「数据库」备份,然后重新运行本命令;')
        print(u'    2) 重新运行时加 --force-backup,本工具会先把整站打包成 tar.gz 再继续。')
        print(u'')
        return False

    dest_dir = os.path.abspath(args.backup_dir) if args.backup_dir else DEFAULT_BACKUP_ROOT
    print(u'  --force-backup 已指定,先自动打包整站到: %s' % dest_dir)
    try:
        bpath = make_backup(site_dir, dest_dir)
    except (IOError, OSError, tarfile.TarError) as e:
        sys.stderr.write(u'错误: 自动备份失败,拒绝继续执行: %s\n' % e)
        return False
    print(u'  [通过] 自动备份完成: %s(%.1f MB)'
          % (bpath, os.path.getsize(bpath) / 1048576.0))
    print(u'')
    return True


# ---------------------------------------------------------------------------
# 闸门 3: 健康回归(操作前后 URL 快照对比)
# ---------------------------------------------------------------------------

def http_get(url):
    """发起 GET 请求,返回 (状态码, 响应体文本)。网络异常时抛出,由调用方记录。"""
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    try:
        resp = urllib.request.urlopen(req, timeout=HTTP_TIMEOUT)
        body = resp.read(2 * 1024 * 1024).decode('utf-8', 'ignore')
        code = resp.getcode()
        resp.close()
        return code, body
    except urllib.error.HTTPError as e:
        body = b''
        try:
            body = e.read(512 * 1024)
        except Exception:
            pass
        return e.code, body.decode('utf-8', 'ignore')


def extract_markers(body):
    """从页面提取"关键标记": 标题、generator、最长的两段中文。
    操作后这些标记消失,说明页面已经不是原来那个页面了。"""
    markers = []
    m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
    if m:
        t = re.sub(r'\s+', ' ', m.group(1)).strip()
        if len(t) >= 4:
            markers.append(t)
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if m:
        markers.append(m.group(1))
    cjk = re.findall(u'[一-鿿]{6,}', body)
    cjk.sort(key=len, reverse=True)
    for c in cjk[:2]:
        if c not in markers:
            markers.append(c)
    return markers[:4]


def snapshot_health(base_url):
    """抓站点关键 URL 快照: 首页 / wp-login / 一篇文章(?p=1)。
    每个 URL 记录 HTTP 状态、内容长度、关键标记;_body 仅供内存对比,不写盘。"""
    urls = [base_url + '/', base_url + '/wp-login.php', base_url + '/?p=1']
    snap = {}
    for u in urls:
        try:
            code, body = http_get(u)
            snap[u] = {'http': code, 'len': len(body),
                       'markers': extract_markers(body), '_body': body}
        except Exception as e:
            snap[u] = {'error': u'%s' % e}
    return snap


def public_snapshot(snap):
    """去掉 _body,得到可写进 manifest 的快照"""
    if snap is None:
        return None
    out = {}
    for u, e in snap.items():
        out[u] = dict((k, v) for k, v in e.items() if k != '_body')
    return out


def compare_health(before, after):
    """对比操作前后快照,返回异常描述列表(空列表 = 健康)"""
    problems = []
    for u, b in before.items():
        a = after.get(u)
        if a is None:
            continue
        if 'error' in b:
            continue  # 操作前就拿不到,没有可比基线
        if 'error' in a:
            problems.append(u'%s 操作后无法访问: %s' % (u, a['error']))
            continue
        if b.get('http', 0) < 500 and a.get('http', 0) >= 500:
            problems.append(u'%s 状态码由 %s 变为 %s(5xx)' % (u, b.get('http'), a.get('http')))
        blen = b.get('len', 0)
        alen = a.get('len', 0)
        if blen > 0 and abs(alen - blen) / float(blen) > LEN_TOLERANCE:
            problems.append(u'%s 内容长度由 %d 变为 %d,偏差超过 %.0f%%'
                            % (u, blen, alen, LEN_TOLERANCE * 100))
        abody = a.get('_body', u'')
        for m in b.get('markers', []):
            if m and m not in abody:
                problems.append(u'%s 关键标记消失: %s' % (u, m[:50]))
    return problems


# ---------------------------------------------------------------------------
# 闸门 2: 隔离不删 + manifest
# ---------------------------------------------------------------------------

def prepare_quarantine_dir(args, site_dir):
    """创建本次操作的隔离目录 <base>/quarantine-YYYYmmdd-HHMM(-N)/files。
    安全校验: 隔离区必须位于站点目录之外。"""
    base = os.path.abspath(args.quarantine_dir) if args.quarantine_dir else DEFAULT_BACKUP_ROOT
    site_prefix = site_dir.rstrip(os.sep) + os.sep
    if base.startswith(site_prefix) or base == site_dir.rstrip(os.sep):
        sys.stderr.write(u'错误: 隔离目录不能放在站点目录里面(那等于没隔离): %s\n' % base)
        return None
    stamp = time.strftime('%Y%m%d-%H%M')
    qdir = os.path.join(base, 'quarantine-' + stamp)
    n = 2
    while os.path.exists(qdir):
        qdir = os.path.join(base, 'quarantine-%s-%d' % (stamp, n))
        n += 1
    try:
        os.makedirs(os.path.join(qdir, 'files'))
    except (IOError, OSError) as e:
        sys.stderr.write(u'错误: 隔离目录创建失败: %s(%s)\n' % (qdir, e))
        return None
    return qdir


def save_manifest(mpath, m):
    with open(mpath, 'w', encoding='utf-8') as f:
        json.dump(m, f, ensure_ascii=False, indent=2)


def quarantine_files(site_dir, qdir, resolved):
    """逐个把文件移入隔离区(保留相对路径结构),返回 manifest entries。
    全程只有 shutil.move,没有任何直接删除站点文件的调用。"""
    entries = []
    for ap, rel, reasons in resolved:
        dst = os.path.join(qdir, 'files', rel)
        parent = os.path.dirname(dst)
        if not os.path.isdir(parent):
            os.makedirs(parent)
        digest = sha256_file(ap)
        st = os.stat(ap)
        shutil.move(ap, dst)
        entries.append({
            'relative_path': rel,
            'original_path': ap,
            'quarantine_path': os.path.abspath(dst),
            'sha256': digest,
            'size': st.st_size,
            'mtime': fmt_time(st.st_mtime),
            'reasons': reasons,
            'quarantined_at': now_str(),
            'status': 'quarantined',
        })
        print(u'  [已隔离] %s' % rel)
    return entries


def rollback_manifest(mpath, dry_run=False):
    """按 manifest 把处于"已隔离"状态的文件移回原位,并校验 hash。
    安全规则: 原位置已有文件时不覆盖(跳过并提示人工处理)。返回是否全部成功。"""
    try:
        with open(mpath, 'r', encoding='utf-8') as f:
            m = json.load(f)
    except (IOError, OSError, ValueError) as e:
        sys.stderr.write(u'错误: 无法读取 manifest: %s(%s)\n' % (mpath, e))
        return False

    todo = [e for e in m.get('entries', []) if e.get('status') == 'quarantined']
    if not todo:
        print(u'manifest 中没有处于"已隔离"状态的文件(可能已回滚过),无事可做。')
        return True

    print(u'回滚 %d 个文件(manifest: %s)%s'
          % (len(todo), mpath, u' —— 演习模式,不动手' if dry_run else u''))
    ok = True
    for e in todo:
        src = e.get('quarantine_path')
        dst = e.get('original_path')
        rel = e.get('relative_path', dst)
        if dry_run:
            print(u'  [演习] 将移回 %s → %s' % (src, dst))
            continue
        if not src or not os.path.isfile(src):
            print(u'  [失败] 隔离文件已不存在: %s' % src)
            ok = False
            continue
        if os.path.exists(dst):
            print(u'  [跳过] 原位置已有文件,为避免覆盖不回滚: %s(请人工处理)' % dst)
            ok = False
            continue
        try:
            parent = os.path.dirname(dst)
            if parent and not os.path.isdir(parent):
                os.makedirs(parent)
            shutil.move(src, dst)
        except (IOError, OSError, shutil.Error) as ex:
            print(u'  [失败] 移回失败 %s: %s' % (rel, ex))
            ok = False
            continue
        if e.get('sha256') and sha256_file(dst) != e['sha256']:
            print(u'  [警告] 回滚后 hash 与操作前不一致: %s(请人工核对)' % rel)
            e['status'] = 'restored_hash_mismatch'
            ok = False
        else:
            print(u'  [已回滚] %s' % rel)
            e['status'] = 'restored'

    if not dry_run:
        m['status'] = 'rolled_back'
        m['rolled_back_at'] = now_str()
        save_manifest(mpath, m)
        print(u'manifest 已更新: status=rolled_back')
    return ok


# ---------------------------------------------------------------------------
# 报告解析
# ---------------------------------------------------------------------------

def load_report_targets(report_path, site_dir):
    """读取 sr-scan JSON 报告,把【高危】条目按文件去重,返回 [(rel_path, [reasons])]。
    无文件路径的网络/全站类高危不在文件隔离范围,跳过并提示。"""
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (IOError, OSError, ValueError) as e:
        sys.stderr.write(u'错误: 无法读取报告文件: %s(%s)\n' % (report_path, e))
        return None

    if data.get('tool') != 'sr-scan':
        print(u'警告: 该文件可能不是 sr-scan 报告(tool=%s),仍将尝试解析' % data.get('tool'))

    rtarget = data.get('target')
    if rtarget and os.path.abspath(rtarget) != site_dir:
        print(u'警告: 报告扫描目标(%s)与传入站点目录不一致,' % rtarget)
        print(u'      将以传入目录(%s)为准解析相对路径。' % site_dir)

    targets = {}
    skipped = 0
    for e in data.get('high', []):
        p = e.get('path')
        if not p:
            skipped += 1
            continue
        reason = e.get('reason', u'')
        if e.get('line') is not None:
            reason = u'%s(第 %s 行)' % (reason, e['line'])
        targets.setdefault(p, []).append(reason)

    if skipped:
        print(u'提示: %d 条高危没有文件路径(网络/全站类),不在文件隔离范围,已跳过。' % skipped)
    print(u'从报告中读到 %d 个唯一高危文件。' % len(targets))
    return sorted(targets.items())


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def collect_targets(args, site_dir):
    """汇总待隔离文件: 解析来源(报告/手动)→ 校验在站点内且存在 → 去重"""
    if args.from_report:
        pairs = load_report_targets(args.from_report, site_dir)
        if pairs is None:
            return None
    else:
        reason = args.reason if args.reason else u'手动指定隔离'
        pairs = [(p, [reason]) for p in args.quarantine]

    resolved = []
    seen = set()
    for given, reasons in pairs:
        ap = resolve_site_file(site_dir, given)
        if ap is None:
            print(u'  [拒绝] 路径不在站点目录内: %s' % given)
            continue
        if not os.path.isfile(ap):
            print(u'  [跳过] 文件不存在或不是普通文件: %s' % given)
            continue
        if ap in seen:
            continue
        seen.add(ap)
        resolved.append((ap, rel_display(ap, site_dir), reasons))
    return resolved


def print_dry_run(args, site_dir, resolved):
    print(u'===== 演习模式(--dry-run):只打印计划,不会改动/创建任何文件 =====')
    print(u'站点目录: %s' % site_dir)
    # 闸门 1 在演习下只警告不阻断
    search_dirs = ([args.backup_dir] if args.backup_dir else []) + [DEFAULT_BACKUP_ROOT]
    found = find_recent_backup(search_dirs)
    if found:
        print(u'备份门禁: [通过] 24 小时内的备份: %s(%s)' % (found[0], fmt_time(found[1])))
    else:
        print(u'备份门禁: [警告] 未发现 24 小时内的备份 —— 正式执行将被拒绝,')
        print(u'          请先备份,或加 --force-backup 让工具先自动打包。')
        if args.force_backup:
            dest = os.path.abspath(args.backup_dir) if args.backup_dir else DEFAULT_BACKUP_ROOT
            print(u'          (已指定 --force-backup:正式执行时将先打包整站到 %s)' % dest)
    qbase = os.path.abspath(args.quarantine_dir) if args.quarantine_dir else DEFAULT_BACKUP_ROOT
    print(u'隔离区: %s 下的 quarantine-<时间戳>/' % qbase)
    print(u'将隔离 %d 个文件:' % len(resolved))
    for _ap, rel, reasons in resolved:
        print(u'  - %s' % rel)
        for r in reasons:
            print(u'      原因: %s' % r)
    if args.url:
        print(u'健康回归: 将对 %s 的首页/wp-login/一篇文章做操作前后快照对比,异常自动回滚。' % args.url)
    else:
        print(u'健康回归: 未提供 --url,正式执行时将跳过(强烈建议提供)。')
    print(u'===== 演习结束,未做任何改动 =====')


def cmd_repair(args, site_dir):
    resolved = collect_targets(args, site_dir)
    if resolved is None:
        return 2
    if not resolved:
        print(u'没有需要隔离的文件,无事可做。')
        return 0

    if args.dry_run:
        print_dry_run(args, site_dir, resolved)
        return 0

    print(u'站点目录: %s' % site_dir)
    print(u'待隔离文件: %d 个' % len(resolved))
    print(u'')

    # ---- 闸门 1: 备份门禁 ----
    if not gate_backup(args, site_dir):
        return 3

    # ---- 闸门 3 前置: 操作前快照 ----
    before = None
    base_url = args.url.rstrip('/') if args.url else None
    if base_url:
        print(u'抓取操作前站点快照(%s)...' % base_url)
        before = snapshot_health(base_url)
        for u, e in before.items():
            if 'error' in e:
                print(u'  %s → 访问失败: %s' % (u, e['error']))
            else:
                print(u'  %s → HTTP %s,%d 字节,%d 个关键标记'
                      % (u, e['http'], e['len'], len(e['markers'])))
        print(u'')
    else:
        print(u'★ 警告: 未提供 --url,闸门 3(健康回归)无法执行,本次跳过。')
        print(u'        强烈建议提供站点 URL,以便操作后自动验证站点健康。')
        print(u'')

    # ---- 闸门 2: 隔离不删 ----
    print(u'===== 闸门 2/3: 隔离(只移不删,全程留证) =====')
    qdir = prepare_quarantine_dir(args, site_dir)
    if qdir is None:
        return 2
    entries = quarantine_files(site_dir, qdir, resolved)
    print(u'隔离目录: %s' % qdir)

    manifest = {
        'tool': 'sr-repair',
        'version': TOOL_VERSION,
        'created_at': now_str(),
        'site_dir': site_dir,
        'site_url': base_url,
        'quarantine_dir': qdir,
        'health_before': public_snapshot(before),
        'entries': entries,
        'status': 'quarantined',
    }
    mpath = os.path.join(qdir, 'manifest.json')
    save_manifest(mpath, manifest)
    print(u'manifest 已写入: %s' % mpath)
    print(u'')

    # ---- 闸门 3: 健康回归 ----
    if before is not None:
        print(u'===== 闸门 3/3: 健康回归 =====')
        after = snapshot_health(base_url)
        anomalies = compare_health(before, after)
        manifest['health_after'] = public_snapshot(after)
        if anomalies:
            manifest['health_anomalies'] = anomalies
            save_manifest(mpath, manifest)
            print(u'★ 站点健康异常,触发自动回滚:')
            for a in anomalies:
                print(u'  - %s' % a)
            print(u'')
            rollback_manifest(mpath)
            print(u'')
            print(u'回滚后复测:')
            recheck = snapshot_health(base_url)
            rec_anomalies = compare_health(before, recheck)
            if rec_anomalies:
                print(u'★ 警告: 回滚后站点仍未完全恢复,请立即人工检查:')
                for a in rec_anomalies:
                    print(u'  - %s' % a)
            else:
                print(u'  快照已恢复与操作前一致,站点应已回到操作前状态。')
            return 4
        save_manifest(mpath, manifest)
        print(u'  复抓快照与操作前一致:状态码/内容长度/关键标记均未见异常。')
        manifest['status'] = 'completed'
        save_manifest(mpath, manifest)
        print(u'')

    # ---- 收尾 ----
    print(u'===== 操作完成 =====')
    print(u'已隔离 %d 个文件,原位置已清空;文件在隔离区完好保存,可随时回滚。' % len(entries))
    if before is None:
        print(u'注意: 本次未做健康回归(未提供 --url),请立即手动访问网站确认显示正常。')
    print(u'回滚命令: python3 sr-repair.py --rollback %s' % mpath)
    print(u'下一步: 改全部密码(宝塔/WP 后台/数据库/FTP/SSH)→ 更新核心与全部插件主题')
    print(u'        → 找根因 → 加固。详见 runbook: %s' % RUNBOOK_URL)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=u'宝塔 + WordPress 被黑站修复安全骨架(三闸门:备份门禁/隔离不删/健康回归)')
    parser.add_argument('site_dir', nargs='?', default=None,
                        help=u'WordPress 站点根目录,如 /www/wwwroot/mysite.com(--rollback 模式不需要)')
    src = parser.add_mutually_exclusive_group()
    src.add_argument('--from-report', dest='from_report', default=None,
                     help=u'读取 sr-scan 的 JSON 报告,把【高危】文件全部过隔离流程')
    src.add_argument('--quarantine', dest='quarantine', nargs='+', default=None,
                     metavar='FILE',
                     help=u'手动指定要隔离的文件(相对站点目录或绝对路径),可多个')
    parser.add_argument('--rollback', dest='rollback', default=None,
                        metavar='MANIFEST',
                        help=u'按 manifest.json 回滚某次隔离(此模式不需要 site_dir)')
    parser.add_argument('--reason', dest='reason', default=None,
                        help=u'手动隔离时写入 manifest 的原因说明(默认"手动指定隔离")')
    parser.add_argument('--url', dest='url', default=None,
                        help=u'站点 URL,提供后启用闸门 3 健康回归(强烈建议提供)')
    parser.add_argument('--backup-dir', dest='backup_dir', default=None,
                        help=u'备份目录(优先于宝塔默认 /www/backup 检查;--force-backup 也写到这里)')
    parser.add_argument('--quarantine-dir', dest='quarantine_dir', default=None,
                        help=u'隔离区根目录(默认 /www/backup),每次操作在下面新建 quarantine-时间戳 子目录')
    parser.add_argument('--force-backup', dest='force_backup', action='store_true',
                        help=u'备份门禁未通过时,先把整站打包成 tar.gz 再继续')
    parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                        help=u'演习模式:只打印将做什么,不动手(备份门禁只警告不阻断)')
    args = parser.parse_args(argv)

    if args.rollback:
        return 0 if rollback_manifest(args.rollback, dry_run=args.dry_run) else 1

    if not args.site_dir:
        sys.stderr.write(u'错误: 需要站点目录参数(--rollback 模式除外)\n')
        return 2
    site_dir = os.path.abspath(args.site_dir)
    if not os.path.isdir(site_dir):
        sys.stderr.write(u'错误: 目录不存在或不是目录: %s\n' % args.site_dir)
        return 2
    if not args.from_report and not args.quarantine:
        sys.stderr.write(u'错误: 需要 --from-report <报告> 或 --quarantine <文件...> 之一\n')
        return 2

    return cmd_repair(args, site_dir)


if __name__ == '__main__':
    sys.exit(main())
