#!/usr/bin/env python3
"""Transactional, fail-closed migration for the pinned jieshu installation.

Standard library only. No metadata is evaluated as shell. Secrets are never
included in diagnostics. See docs/SOURCE_AUDIT.md and README.md before use.
"""
import argparse
import base64
import contextlib
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import urllib.parse
import uuid
import zlib

VERSION = '0.1.0'
PROFILE = globals().get('PROFILE') or json.loads(Path(__file__).with_name('compatibility.json').read_text())
STATE = Path('/var/lib/qianyi')
PROGRAM = '/usr/local/lib/qianyi/agent.py'
VR = '/var/lib/vless-reality'
UNIT = '/etc/systemd/system'
TAG_RE = re.compile(r'vless-temp-[A-Za-z0-9._-]{1,96}\Z')
SID_RE = re.compile(r'[0-9a-f]{32}\Z')
TIMERS = ['vless-gc.timer', 'pq-save.timer', 'pq-reset.timer', 'vless-managed-watchdog.timer']
WORKERS = ['vless-gc.service', 'pq-save.service', 'pq-reset.service',
           'vless-managed-watchdog.service', 'vless-managed-restore.service',
           'vless-managed-shutdown-save.service']
OPTIONAL = ['portbw-watch.service', 'portbw-restore.service']
LOCKS = ['/run/vless-reality/temp.lock', '/run/vless-reality/portquota.lock',
         '/run/vless-reality/iplimit.lock', '/run/portbw/manager.lock',
         '/run/jsh-ipban.lock', '/run/jsh-cidrban.lock']
LIB_PREFIX = 'set -Eeuo pipefail\nsource /usr/local/lib/vless-reality/quota-lib.sh\nsource /usr/local/lib/vless-reality/iplimit-lib.sh\n'


class Error(Exception):
    pass


def need(test, message):
    if not test:
        raise Error(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(obj):
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':'))+'\n').encode()


def run(args, data=None, check=True, timeout=60, env=None):
    """Never echo subprocess arguments/stderr: either can contain credentials."""
    try:
        r = subprocess.run([str(a) for a in args], input=data, capture_output=True,
                           timeout=timeout, env=dict(os.environ, LC_ALL='C', **(env or {})))
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Error(f'{Path(str(args[0])).name} 执行失败或超时') from e
    if check and r.returncode:
        raise Error(f'{Path(str(args[0])).name} 返回失败 ({r.returncode})；未输出可能含凭据的诊断')
    return r


def output(args, **kwargs):
    return run(args, **kwargs).stdout.decode().strip()


def jsoncmd(args):
    try:
        return json.loads(output(args))
    except (ValueError, UnicodeError) as e:
        raise Error(f'{args[0]} 返回无法解析的 JSON，拒绝继续') from e


def regular(path, required=True):
    p = Path(path)
    if not p.exists() and not p.is_symlink():
        need(not required, f'缺少文件：{p}')
        return None
    s = p.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
         f'文件不是 root 管理的普通文件或可被其他用户修改：{p}')
    return p.read_bytes()


def atomic(path, data, mode=0o600):
    p = Path(path)
    # Reject symlinks in every existing ancestor, including dangling symlinks.
    for parent in [p, *p.parents]:
        need(not parent.is_symlink(), f'拒绝符号链接：{parent}')
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.qianyi-', dir=p.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), mode)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, p)
        fd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save(path, obj):
    atomic(path, encoded(obj))


def read_json(path):
    try:
        return json.loads(regular(path))
    except (ValueError, UnicodeError) as e:
        raise Error(f'JSON 损坏：{path}') from e


def metadata(data):
    result = {}
    for line in data.decode().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        need('=' in line, '元数据含非键值行')
        k, v = line.split('=', 1)
        need(re.fullmatch(r'[A-Z][A-Z0-9_]*', k) and k not in result,
             '元数据含重复或非法字段')
        result[k] = v
    return result


def env_bytes(m):
    need(all('\n' not in str(v) and '\r' not in str(v) for v in m.values()), '元数据值包含换行')
    return ''.join(f'{k}={v}\n' for k, v in m.items()).encode()


def uint(value, name='数字', maximum=2**63-1):
    need(re.fullmatch(r'0|[1-9][0-9]*', str(value)) is not None, f'{name} 非法')
    n = int(value)
    need(0 <= n <= maximum, f'{name} 超出范围')
    return n


def node_paths(tag, port):
    need(bool(TAG_RE.fullmatch(tag)) and 1 <= int(port) <= 65535 and int(port) != 443, '节点标识/端口非法')
    return {'meta': f'{VR}/temp/{tag}.env', 'url': f'{VR}/temp/{tag}.url',
            'config': f'/usr/local/etc/xray/{tag}.json', 'unit': f'{UNIT}/{tag}.service',
            'quota': f'{VR}/quota/{port}.env', 'iplimit': f'{VR}/iplimit/{port}.env'}


def public_key(private):
    try:
        raw = base64.urlsafe_b64decode(private+'='*((-len(private)) % 4))
        need(len(raw) == 32, 'Reality 私钥长度异常')
        der = bytes.fromhex('302e020100300506032b656e04220420')+raw
        r = run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'], data=der)
        need(r.stdout[:12] == bytes.fromhex('302a300506032b656e032100') and len(r.stdout) == 44,
             '无法核对 Reality 公钥')
        return base64.urlsafe_b64encode(r.stdout[12:]).decode().rstrip('=')
    except (ValueError, TypeError) as e:
        raise Error('Reality 密钥格式异常') from e


def canonical_unit(m):
    text = PROFILE['templates']['nat' if m.get('LANDING') == 'nat' else 'direct']
    values = dict(m, CFG=f'/usr/local/etc/xray/{m["TAG"]}.json', META=f'{VR}/temp/{m["TAG"]}.env')
    text = re.sub(r'\$\{([A-Z_]+)\}', lambda x: values[x[1]], text)
    need('${' not in text, '无法渲染节点服务')
    return text


def validate_node(node):
    m = node['meta']; tag = m['TAG']; port = uint(m['PORT'], '端口', 65535)
    node_paths(tag, port)
    need(tag == 'vless-temp-'+m['ID'], f'{tag} ID 与 TAG 不一致')
    need(m.get('IP_VERSION', '4') == '4' and m['LISTEN_ADDR'] == '0.0.0.0', f'{tag} 不是标准 IPv4 入站')
    need(m.get('LANDING', '') in ('', 'nat'), f'{tag} 未知节点类型')
    for k in ['CREATE_EPOCH', 'EXPIRE_EPOCH', 'DURATION_SECONDS', 'IP_LIMIT', 'IP_STICKY_SECONDS']:
        uint(m[k], k)
    need(uint(m['EXPIRE_EPOCH']) - uint(m['CREATE_EPOCH']) == uint(m['DURATION_SECONDS']), '有效期字段不一致')
    need(0 < uint(m['IP_STICKY_SECONDS']) <= 2147483647 and uint(m['IP_LIMIT']) <= 65535, 'IP 策略非法')
    c = json.loads(node['config'])
    need(set(c) <= {'log', 'inbounds', 'outbounds', 'routing'}, f'{tag} 有未经审计的 Xray 顶层配置')
    need(len(c['inbounds']) == 1, f'{tag} 入站数量异常')
    inbound = c['inbounds'][0]; s = inbound['streamSettings']; r = s['realitySettings']
    need(inbound['port'] == port and inbound['listen'] == '0.0.0.0' and inbound['protocol'] == 'vless', '入站与元数据不一致')
    need(inbound['settings'] == {'clients':[{'id':m['UUID'], 'flow':'xtls-rprx-vision'}], 'decryption':'none'}, 'UUID/flow 配置不兼容')
    need(s['network'] == 'tcp' and s['security'] == 'reality', '仅支持已审计的 TCP Reality')
    need(r['dest'] == m['REALITY_DEST'] and r['serverNames'] == [m['REALITY_SNI']] and
         r['shortIds'] == [m['SHORT_ID']], 'Reality 元数据不一致')
    need(public_key(r['privateKey']) == m['PBK'], f'{tag} 公私钥不匹配')
    link = urllib.parse.urlsplit(node['url'].strip())
    query = urllib.parse.parse_qs(link.query, strict_parsing=True)
    need(all(len(v) == 1 for v in query.values()), '链接参数重复')
    need(link.scheme == 'vless' and link.username == m['UUID'] and link.port == port and
         link.hostname == m['PUBLIC_DOMAIN'].lower(), '原链接域名/端口/UUID 与节点不一致')
    need(not re.fullmatch(r'[0-9.]+', link.hostname or '') and re.fullmatch(r'[A-Za-z0-9.-]+', link.hostname or ''), '需要业务域名链接')
    for k, v in {'pbk':m['PBK'], 'sid':m['SHORT_ID'], 'sni':m['REALITY_SNI'],
                 'type':'tcp', 'security':'reality', 'encryption':'none', 'flow':'xtls-rprx-vision'}.items():
        need(query.get(k) == [v], f'{tag} 链接认证参数 {k} 不一致')
    need(node['unit'] == canonical_unit(m), f'{tag} systemd 服务不是已审计模板')
    if m.get('LANDING') == 'nat':
        for k in ['MARK', 'TABLE_ID', 'RULE_PRIORITY', 'HANDSHAKE_MAX']:
            need(uint(m[k], k) > 0, 'WG 参数非法')
        need(re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', m['WG_IF']) and m['WG_IF'] not in ('.', '..'), 'WG 接口非法')
        want = [{'tag':'nat', 'protocol':'freedom', 'settings':{'domainStrategy':'UseIPv4'},
                 'streamSettings':{'sockopt':{'mark':int(m['MARK'])}}}, {'tag':'block','protocol':'blackhole'}]
        need(c['outbounds'] == want and c['routing'] == {'rules':[{'type':'field', 'inboundTag':[tag], 'outboundTag':'nat'}]}
             and inbound.get('tag') == tag, 'NAT 标记/路由不匹配')
    else:
        need(c['outbounds'] == [{'tag':'direct','protocol':'freedom'}, {'tag':'block','protocol':'blackhole'}]
             and not c.get('routing'), '普通节点不是标准直出')
    q = node.get('quota')
    need(bool(q) == bool(m.get('PQ_LIMIT_BYTES')), '配额元数据缺失或多余')
    if q:
        for k in ['PORT','ORIGINAL_LIMIT_BYTES','SAVED_USED_BYTES','LIMIT_BYTES','DURATION_SECONDS',
                  'EXPIRE_EPOCH','RESET_INTERVAL_SECONDS','NEXT_RESET_EPOCH','CREATED_EPOCH',
                  'LAST_RESET_EPOCH','LAST_SAVE_EPOCH','REBUILD_PENDING']:
            uint(q[k], k)
        need(q['PORT'] == m['PORT'] and q['OWNER_TAG'] == tag and q['OWNER_KIND'] == 'temp', '配额归属不一致')
        need(q['ORIGINAL_LIMIT_BYTES'] == m['PQ_LIMIT_BYTES'] and q['EXPIRE_EPOCH'] == m['EXPIRE_EPOCH'], '配额/节点限额或有效期不一致')
        need(uint(q['SAVED_USED_BYTES']) + uint(q['LIMIT_BYTES']) == uint(q['ORIGINAL_LIMIT_BYTES']), '配额余额不守恒')
        need(q['REBUILD_PENDING'] == '0', '配额存在未完成事务，需先修复后迁移')
        need(uint(q['RESET_INTERVAL_SECONDS']) in (0,2592000), '未知配额周期')
        need(bool(uint(q['RESET_INTERVAL_SECONDS'])) == bool(uint(q['NEXT_RESET_EPOCH'])), '重置周期/日期不一致')
    il = node.get('iplimit')
    need(bool(il) == (int(m['IP_LIMIT']) > 0), 'IP 限制元数据缺失或多余')
    if il:
        need(il['OWNER_TAG'] == tag and il['OWNER_KIND'] == 'temp' and il['PORT'] == m['PORT'], 'IP 限制归属异常')
        for k in ('IP_LIMIT','IP_STICKY_SECONDS','IP_VERSION'):
            need(il[k] == m[k], 'IP 限制与节点字段不一致')
        need(il['SET_NAME'] == 'vr_il4_'+m['PORT'], 'IP 集合名称异常')
    return node


def settled_quota(q, live, now):
    q = dict(q)
    used = min(uint(q['ORIGINAL_LIMIT_BYTES']), uint(q['SAVED_USED_BYTES'])+uint(live))
    q.update(SAVED_USED_BYTES=str(used), LIMIT_BYTES=str(uint(q['ORIGINAL_LIMIT_BYTES'])-used),
             LAST_SAVE_EPOCH=str(now), REBUILD_PENDING='0')
    return q


def apply_due(q, now):
    """Match vr_pq_reset_due_one exactly; never postpone expiry."""
    q = dict(q)
    interval = uint(q['RESET_INTERVAL_SECONDS']); nxt = uint(q['NEXT_RESET_EPOCH'])
    expiry = uint(q['EXPIRE_EPOCH'])
    if interval and nxt and now >= nxt and not (expiry and expiry <= now):
        nxt += ((now-nxt)//interval+1)*interval
        q.update(SAVED_USED_BYTES='0', LIMIT_BYTES=q['ORIGINAL_LIMIT_BYTES'], NEXT_RESET_EPOCH=str(nxt),
                 LAST_RESET_EPOCH=str(now), LAST_SAVE_EPOCH=str(now), REBUILD_PENDING='0')
    return q


def quota_live(q, rows):
    """Strict dual-view read. Fully settled exhausted quota is the only no-counter case."""
    p = q['PORT']; table = [x for x in rows if next(iter(x.values()), {}).get('table') == 'vr_pq']
    counters = {x['counter']['name']:x['counter'] for x in table if 'counter' in x}
    quotas = {x['quota']['name']:x['quota'] for x in table if 'quota' in x}
    rules = {x['rule'].get('comment'):x['rule'] for x in table if 'rule' in x}
    drops = ['vr-pq-drop-'+d+'-'+p for d in ('in','out')]
    need(all(k in rules for k in drops), f'{p} 缺失配额阻断规则')
    if q['LIMIT_BYTES'] == '0':
        need(all(rules[k]['expr'][-1] == {'drop':None} for k in drops), '耗尽规则异常')
        need(not any('quota' in e for k in drops for e in rules[k]['expr']), '耗尽配额仍是条件规则')
        need('vr_pq_q_'+p not in quotas and 'vr_pq_in_'+p not in counters and 'vr_pq_out_'+p not in counters,
             '已耗尽持久状态仍有旧计数对象')
        return 0
    try:
        quota = quotas['vr_pq_q_'+p]
        need(uint(quota['bytes']) == uint(q['LIMIT_BYTES']) and quota.get('inv') is True, '内核 quota 限额不匹配')
        a = uint(quota['used'])
        b = uint(counters['vr_pq_in_'+p]['bytes'])+uint(counters['vr_pq_out_'+p]['bytes'])
    except KeyError as e:
        raise Error(f'{p} 实时计数缺失，不能按零结算') from e
    need(all('vr-pq-count-'+d+'-'+p in rules for d in ('in','out')), '缺失配额计数规则')
    return max(a, b)


def load_module(path, name):
    raw = regular(path)
    need(digest(raw) == PROFILE['files'][path], f'未支持的已安装版本：{path}')
    module = types.ModuleType(name)
    module.__file__ = path
    exec(compile(raw, path, 'exec'), module.__dict__)
    return module


def rebase_bandwidth(rec, origin_wall, now, boot_now, boot_id):
    rec = copy.deepcopy(rec)
    rec.pop('tc_prefs', None)  # local interface slot allocation must be fresh
    rec['pending'] = True
    if 'auto' not in rec:
        return rec
    rt = rec['runtime']; rt['boot_id'] = boot_id; rt['checked_at'] = None
    for d, s in rt['dirs'].items():
        # CLOCK_BOOTTIME values from another machine are never reused directly.
        if s['until'] is not None:
            s['until'] = boot_now + max(0, origin_wall+s['until']-now)
        s.update(last=None, high_since=None, monitor_start_bytes=None, progress=0.0,
                 mbps=None, lower_mbps=None, busy_since=None, last_busy_at=None,
                 reason='迁移后重建采样基线，保留当前策略与截止时间')
    return rec


@contextlib.contextmanager
def locks(paths=LOCKS, readonly=False):
    fds = []
    try:
        for path in paths:
            p = Path(path)
            if readonly and not p.exists():
                continue  # no creation during read-only inspection
            if not readonly:
                p.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            need(not p.is_symlink(), f'锁路径为符号链接：{p}')
            fd = os.open(p, os.O_RDONLY if readonly else os.O_RDWR | os.O_CREAT, 0o600)
            fds.append(fd)
            deadline = time.monotonic()+30
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    need(time.monotonic() < deadline, f'锁繁忙：{p}')
                    time.sleep(.1)
        yield
    finally:
        for fd in reversed(fds):
            os.close(fd)


def library(script):
    return output(['bash', '-c', LIB_PREFIX+script], env={
        'VR_TEMP_LOCK_HELD':'1','VR_PQ_LOCK_HELD':'1','VR_IL_LOCK_HELD':'1'})


def systemctl(*args, check=True):
    return output(['systemctl', *args], check=check, timeout=150)


def active(unit):
    return systemctl('show', '-p', 'ActiveState', '--value', unit)


def nft_rows():
    obj = jsoncmd(['nft','-j','-n','-a','list','ruleset'])
    need(isinstance(obj.get('nftables'), list), 'nftables 快照无效')
    return obj['nftables']


def nft(script):
    run(['nft','-f','-'], data=script.encode())


def machine_id():
    return regular('/etc/machine-id').decode().strip()


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def boottime():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def check_profile(nat=False, bw=False):
    for path, expected in PROFILE['files'].items():
        if path.startswith('/usr/local/lib/portbw/'):
            if not bw:
                continue
        elif 'nat_' in path or 'mktemp_nat' in path:
            if not nat:
                continue
        raw = regular(path)
        need(digest(raw) == expected, f'安装版本不受支持（SHA-256 不匹配）：{path}')
    for unit in TIMERS+WORKERS:
        drop = systemctl('show', '-p', 'DropInPaths', '--value', unit).split()
        need(all(p == f'{UNIT}/{unit}.d/90-qianyi-hold.conf' for p in drop), f'未知服务覆盖：{unit}')
    need(systemctl('is-active','xray.service') == 'active', '目标或源 443 主服务未正常运行')


def environment():
    need(os.geteuid() == 0, '请使用 root 运行')
    osr = metadata(regular('/usr/lib/os-release' if Path('/etc/os-release').is_symlink() else '/etc/os-release'))
    need(osr.get('ID','').strip('"') == 'debian' and osr.get('VERSION_ID','').strip('"') == '13', '仅支持 Debian 13')
    need(Path('/run/systemd/system').is_dir(), '需要 systemd')
    for cmd in ['python3','bash','nft','ip','ss','systemctl','openssl','flock','timeout','ssh']:
        need(shutil.which(cmd), f'缺少依赖：{cmd}')
    need(Path('/usr/local/bin/xray').is_file(), '未安装 Xray')
    need(output(['timedatectl','show','-p','NTPSynchronized','--value']) == 'yes', '系统时钟未同步')
    return {'machine':machine_id(), 'boot':boot_id(), 'time':time.time(),
            'xray':output(['/usr/local/bin/xray','version']).splitlines()[0],
            'upstream':PROFILE['commit'], 'tool':VERSION}


def check_wg(m):
    if m.get('LANDING') != 'nat':
        return
    iface = m['WG_IF']
    state = metadata(regular(f'/etc/wireguard/{iface}.env'))
    for k in ['MARK','TABLE_ID','RULE_PRIORITY']:
        need(state[k] == m[k], f'{m["TAG"]} 的 WG {k} 与本机已有配置不匹配')
    need(active(f'wg-quick@{iface}.service') == 'active', f'{iface} 服务未运行')
    route = jsoncmd(['ip','-4','-j','route','get','1.1.1.1','mark',m['MARK']])
    need(len(route) == 1 and route[0].get('dev') == iface, '已有 marked route 不走所需 WG')
    rules = jsoncmd(['ip','-4','-j','rule','show'])
    def as_int(v):
        return int(v,0) if isinstance(v,str) else v
    matches = [r for r in rules if r.get('priority') == int(m['RULE_PRIORITY'])]
    need(len(matches) == 1 and as_int(matches[0].get('fwmark',0)) == int(m['MARK']) and
         str(matches[0].get('table')) == m['TABLE_ID'], '已有 WG 策略路由元组异常')
    routes = jsoncmd(['ip','-4','-j','route','show','table',m['TABLE_ID']])
    need(any(r.get('type') == 'prohibit' and r.get('dst') == 'default' for r in routes), 'WG 缺少禁止直出兜底路由')
    chain = 'VRWO_'+re.sub('[^A-Za-z0-9]', '_', iface).upper()
    output(['iptables','-w','5','-C','OUTPUT','-m','comment','--comment',f'vpswg:{iface}:output','-j',chain])
    output(['iptables','-w','5','-C',chain,'-m','mark','--mark',m['MARK']+'/0xffffffff','!','-o',iface,
            '-j','REJECT','--reject-with','icmp-net-unreachable'])
    hs = output(['wg','show',iface,'latest-handshakes'])
    stamps = [int(x.split()[1]) for x in hs.splitlines() if len(x.split()) == 2]
    need(stamps and 0 <= time.time()-max(stamps) <= int(m.get('HANDSHAKE_MAX','180')), 'WG 无新鲜握手；不自动修复')


def listening():
    text = output(['ss','-H','-ltnu'])
    found = set()
    for line in text.splitlines():
        cols = line.split()
        need(len(cols) >= 5, 'ss 输出格式异常')
        port = cols[4].rsplit(':',1)[-1]
        if port.isdigit():
            found.add(int(port))
    return found


def protected_fingerprints():
    paths = [Path('/usr/local/etc/xray/config.json'),Path(f'{VR}/main/main.env'),
             Path('/etc/default/vless-reality'),Path(f'{UNIT}/xray.service')]
    paths += list(Path('/etc/wireguard').glob('*'))
    paths += list(Path(f'{UNIT}/xray.service.d').glob('*'))
    return {str(p):digest(regular(p)) for p in paths if p.is_file() and not p.is_symlink()}


def check_preserved(before):
    need(all(digest(regular(p)) == h for p,h in before.items()), '443 或 WG 文件发生变化；拒绝开放')


def extract_restrictions(rows, ports):
    result = {p:{'paused':False,'bans':[]} for p in ports}
    tables = {x['table']['name'] for x in rows if 'table' in x}
    for p in ports:
        t = f'pause_vless_{p}'
        if t in tables:
            text = output(['nft','-nn','list','table','inet',t])
            rules = [x['rule'] for x in rows if 'rule' in x and x['rule'].get('table') == t]
            need(len(rules) == 2 and f'iifname != "lo" tcp dport {p} reject with tcp reset' in text and
                 f'iifname != "lo" udp dport {p} drop' in text and 'hook input priority -20;' in text,
                 f'{p} 端口暂停规则不是支持的版本')
            result[p]['paused'] = True
    for x in rows:
        r = x.get('rule',{})
        if r.get('table') == 'jsh_cidrban':
            match = re.fullmatch(r'jshcidr:([1-9][0-9]*):(.+)', r.get('comment',''))
            need(match is not None and r.get('chain') == 'pre', '未知 CIDR 黑名单规则')
            p = int(match[1]); network = str(ipaddress.IPv4Network(match[2],strict=True))
            expr = r['expr']
            need(len(expr) == 5 and expr[-1] == {'drop':None} and 'counter' in expr[-2], '未知黑名单动作')
            source = expr[0].get('match',{})
            expected = str(ipaddress.IPv4Network(network).network_address)
            right = source.get('right')
            valid_addr = right == expected if network.endswith('/32') else right == {'prefix':{'addr':expected,'len':int(network.split('/')[1])}}
            need(source.get('left') == {'payload':{'protocol':'ip','field':'saddr'}} and source.get('op') == '==' and valid_addr,
                 'CIDR 黑名单源地址/注释不一致')
            need(expr[1] == {'match':{'op':'==','left':{'meta':{'key':'l4proto'}},'right':{'set':['tcp','udp']}}}
                 and expr[2] == {'match':{'op':'==','left':{'payload':{'base':'transport header','offset':2,'len':2}},'right':p}},
                 'CIDR 黑名单协议/端口不匹配')
            if p in result:
                result[p]['bans'].append(network)
    if 'jsh_ipban' in tables:
        sets = [x['set'] for x in rows if 'set' in x and x['set'].get('table') == 'jsh_ipban']
        rules = [x['rule'] for x in rows if 'rule' in x and x['rule'].get('table') == 'jsh_ipban']
        need(len(sets) == 1 and sets[0]['name'] == 'banned' and sets[0]['type'] == ['ipv4_addr','inet_service'], '未知旧黑名单集合')
        # Validate the legacy concatenation lookup, not just a trusted-looking table name.
        need(rules and all(r.get('chain') == 'pre' and r['expr'][-1] == {'drop':None}
                          and '@banned' in json.dumps(r) for r in rules), '旧黑名单规则无法识别')
        for e in sets[0].get('elem',[]):
            if 'elem' in e:
                need(set(e['elem']) == {'val'}, '不支持带期限的自定义黑名单')
                e = e['elem']['val']
            need(isinstance(e,dict) and set(e) == {'concat'} and len(e['concat']) == 2, '旧黑名单元素异常')
            addr, p = e['concat']; p = uint(p, '黑名单端口',65535)
            if p in result:
                result[p]['bans'].append(str(ipaddress.IPv4Network(str(addr)+'/32')))
    # Refuse unexplained restrictions rather than silently dropping them. Ordinary
    # host-wide ACCEPT/connection-tracking rules are not migrated.
    known = {'vr_pq','vr_iplimit','vr_daily_traffic','pbw_policy','jsh_cidrban','jsh_ipban','qianyi_fence'}
    known |= {f'pause_vless_{p}' for p in ports}
    for x in rows:
        r = x.get('rule',{})
        if not r or r.get('table') in known:
            continue
        text = json.dumps(r)
        mentions = any(re.search(r'(?<![0-9])'+str(p)+r'(?![0-9])',text) for p in ports)
        restrictive = any('drop' in e or 'reject' in e for e in r.get('expr',[]))
        wg_owned = str(r.get('chain','')).startswith(('VRWO_','VRWI_')) or 'vpswg:' in text
        need(not mentions and not (restrictive and not wg_owned), '存在未知防火墙限制/端口规则，无法安全迁移；请先明确其来源')
    return result


def node_dropin(tag):
    return (f'[Unit]\nRequires=qianyi-boot.service\nAfter=qianyi-boot.service portbw-restore.service\n'
            f'[Service]\nExecStartPre=\nExecStartPre=/usr/bin/python3 {PROGRAM} gate {tag}\n')


def discover():
    nodes = []
    for p in sorted(Path(VR+'/temp').glob('*.env')):
        m = metadata(regular(p)); tag=m.get('TAG',''); port=m.get('PORT','0')
        paths = node_paths(tag,port)
        need(str(p) == paths['meta'], '节点文件名/标识不匹配')
        node = {'meta':m}
        for key in ['url','config','unit']:
            node[key] = regular(paths[key]).decode()
        for key in ['quota','iplimit']:
            raw = regular(paths[key],False)
            node[key] = metadata(raw) if raw is not None else None
        validate_node(node)
        drops = systemctl('show','-p','DropInPaths','--value',tag+'.service').split()
        allowed = f'{UNIT}/{tag}.service.d/80-qianyi.conf'
        need(all(x == allowed and regular(x).decode() == node_dropin(tag) for x in drops), f'{tag} 存在未知服务覆盖')
        state = active(tag+'.service')
        need(state in ('active','inactive','failed'), f'{tag} 服务正在变更，请稍后重试')
        enabled = systemctl('is-enabled',tag+'.service',check=False)
        need(enabled in ('enabled','disabled'), f'{tag} 服务启用状态无法识别')
        node['disabled'] = enabled == 'disabled' or state != 'active'
        nodes.append(node)
    tags = {n['meta']['TAG'] for n in nodes}; ports = {int(n['meta']['PORT']) for n in nodes}
    need(len(ports) == len(nodes), '多个节点占用相同端口')
    expected = {Path(p) for n in nodes for p in node_paths(n['meta']['TAG'],n['meta']['PORT']).values()}
    candidates = list(Path(VR+'/temp').glob('*'))+list(Path('/usr/local/etc/xray').glob('vless-temp-*'))
    candidates += list(Path(UNIT).glob('vless-temp-*.service'))
    for p in candidates:
        need(p in expected, f'存在未知临时节点残留：{p}')
    for directory in ['quota','iplimit']:
        for p in Path(VR+'/'+directory).glob('*.env'):
            m = metadata(regular(p))
            if m.get('OWNER_KIND') == 'temp':
                need(m.get('OWNER_TAG') in tags and p in expected, f'存在孤立归属：{p}')
    loaded = systemctl('list-units','--all','--plain','--no-legend','vless-temp-*.service')
    for line in loaded.splitlines():
        words = line.split()
        if words:
            name = words[0] if words[0].startswith('vless-temp-') else words[1]
            need(name.removesuffix('.service') in tags, '存在无法归属的已加载临时服务')
    return nodes


def bandwidth(nodes, rows, target=False):
    ports = {int(n['meta']['PORT']) for n in nodes}
    path = '/usr/local/lib/portbw/portbw.py'
    present = Path(path).exists()
    need(present or not any(next(iter(x.values()),{}).get('table') == 'pbw_policy' for x in rows), '有未知 portbw 内核残留')
    if not present:
        need(not list(Path('/var/lib/portbw/ports').glob('*')), '限速配置存在但程序缺失')
        return {}
    mod = load_module(path, '_qianyi_portbw')
    config = mod.cfg(); records = mod.records()
    mod.validate_base(mod.nft_snapshot())
    result = {}
    for p in ports:
        if target:
            need(p not in records and not mod.owned(rows,p), f'{p} 目标存在限速残留')
            if config['tc_enabled']:
                for d in ('up','down'):
                    need(not mod.tc_action_exists(mod.tc_police_index(p,d)), f'{p} 目标存在 tc action 冲突')
            continue
        if p in records:
            rec = copy.deepcopy(records[p]); mod.validate_record(p,rec)
            need(not rec.get('pending') and not rec.get('deleting'), f'{p} 限速事务未完成')
            if 'auto' in rec:
                need(rec['runtime']['boot_id'] == boot_id(), '自动限速 boot_id 过期')
                mod.volatile_load(p,rec)
            need(mod.nft_ok(p,rec) and (not config['tc_enabled'] or mod.tc_ok(p,rec,config['iface'])), f'{p} 限速内核审计失败')
            result[str(p)] = rec
    return result


def check_empty(nodes, rows):
    need(not discover(), '目标存在临时用户节点，拒绝覆盖')
    ports = {int(n['meta']['PORT']) for n in nodes}
    need(not (listening() & ports), '目标待迁入端口已被监听（含 TCP/UDP）')
    for n in nodes:
        for p in node_paths(n['meta']['TAG'], n['meta']['PORT']).values():
            need(not Path(p).exists() and not Path(p).is_symlink(), f'目标有残留：{p}')
        need(not Path(f'{UNIT}/{n["meta"]["TAG"]}.service.d').exists(), '目标有服务覆盖残留')
    for x in rows:
        r = next(iter(x.values()), {})
        if r.get('table') in ('vr_pq','vr_iplimit','pbw_policy') or str(r.get('name','')).startswith('pause_vless_'):
            text = json.dumps(x)
            need(not any(re.search(r'(?<![0-9])'+str(p)+r'(?![0-9])',text) for p in ports), '目标有端口防护残留')
    restrictions = extract_restrictions(rows,ports)
    need(not any(r['paused'] or r['bans'] for r in restrictions.values()), '目标有待迁入端口封禁残留')
    bandwidth(nodes,rows,target=True)


def probe(role, manifest=None):
    info = environment()
    with locks(readonly=True):
        nodes = discover() if role == 'source' else manifest['nodes']
        need(nodes, '没有待迁移临时节点')
        need(role != 'source' or not pending_source(), '源机存在未完成迁移，请使用 resume/status')
        rows = nft_rows()
        has_bw = Path('/usr/local/lib/portbw/portbw.py').exists()
        check_profile(any(n['meta'].get('LANDING') == 'nat' for n in nodes), has_bw)
        if role == 'target':
            check_empty(nodes,rows)
            need(not pending_source(), '目标仍是另一轮冻结的源机')
            need(manifest['info']['machine'] != info['machine'], '源机和目标机 machine-id 相同')
            need(manifest['info']['xray'] == info['xray'], '两机 Xray 版本不同')
            need(abs(manifest['info']['time']-info['time']) < 30, '两机时钟或预检请求时间差超过 30 秒')
            need(not manifest.get('bandwidth') or has_bw, '目标缺少对应版本 portbw，请先安装')
        for n in nodes:
            validate_node(n)
            check_wg(n['meta'])
            if role == 'source':
                output(['/usr/local/bin/xray','run','-test','-config',node_paths(n['meta']['TAG'],n['meta']['PORT'])['config']])
                if n['quota']:
                    quota_live(n['quota'],rows)
        if role == 'source':
            restrictions = extract_restrictions(rows,{int(n['meta']['PORT']) for n in nodes})
            for n in nodes:
                n['restrictions'] = restrictions[int(n['meta']['PORT'])]
                n['restrictions']['paused'] |= n['disabled']
            return {'info':info,'nodes':nodes,'bandwidth':bandwidth(nodes,rows), 'protected':protected_fingerprints()}
        return {'info':info, 'protected':protected_fingerprints()}


def session_path(sid):
    need(bool(SID_RE.fullmatch(sid)), '事务编号非法')
    return STATE/'sessions'/sid


def session(sid):
    return read_json(session_path(sid)/'state.json')


def update_session(sid, **fields):
    path = session_path(sid)/'state.json'
    obj = read_json(path) if path.exists() else {}
    obj.update(fields, updated=int(time.time()))
    save(path,obj)
    return obj


def pending_source():
    if not (STATE/'sessions').exists():
        return False
    for p in (STATE/'sessions').glob('*/state.json'):
        s = read_json(p)
        if s.get('role') == 'source' and s.get('phase') in ('FREEZING','SEALED','TRANSFERRING','OPEN_UNCERTAIN'):
            return True
    return False


def program_bytes():
    raw = Path(__file__).read_bytes()
    if globals().get('BUNDLED'):
        return raw
    return ('BUNDLED=True\nPROFILE='+repr(PROFILE)+'\n').encode()+raw


def install_program(data=None):
    data = data or program_bytes()
    old = regular(PROGRAM,False)
    need(old is None or old == data, '已安装其他版本 qianyi；请先完成当前事务，不自动覆盖')
    atomic(PROGRAM,data,0o700)
    text = f'''[Unit]
Description=Restore migration fences and imported node restrictions
After=local-fs.target nftables.service jsh-cidrban.service jsh-ipban.service
Before=vless-managed-restore.service portbw-restore.service portbw-watch.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {PROGRAM} boot
RemainAfterExit=yes
UMask=0077

[Install]
WantedBy=multi-user.target
'''
    path = f'{UNIT}/qianyi-boot.service'
    old = regular(path,False)
    need(old is None or old.decode() == text, '未知 qianyi-boot.service')
    atomic(path,text.encode(),0o644)
    systemctl('daemon-reload')
    systemctl('enable','qianyi-boot.service')


def owners():
    path=STATE/'owners.json'
    return read_json(path) if path.exists() else {}


def hold_nodes(sid, nodes):
    mapping=owners()
    for n in nodes:
        tag=n['meta']['TAG']
        mapping[tag]=sid
        atomic(f'{UNIT}/{tag}.service.d/80-qianyi.conf',node_dropin(tag).encode(),0o644)
        atomic(f'{UNIT}/{tag}.service.d/90-qianyi-hold.conf',
               f'[Unit]\nConditionPathExists=!{STATE}/holds/{tag}\n[Service]\nExecStopPost=\n'.encode(),0o644)
        atomic(STATE/'holds'/tag,b'held\n')
    save(STATE/'owners.json',mapping)
    systemctl('daemon-reload')


def release_nodes(nodes):
    for n in nodes:
        tag=n['meta']['TAG']
        (STATE/'holds'/tag).unlink(missing_ok=True)
        Path(f'{UNIT}/{tag}.service.d/90-qianyi-hold.conf').unlink(missing_ok=True)
    systemctl('daemon-reload')


def pause_workers(sid):
    s=session(sid)
    if 'workers' not in s:
        units=TIMERS+WORKERS
        units += [u for u in OPTIONAL if systemctl('show','-p','LoadState','--value',u) != 'not-found']
        states={u:active(u) for u in units}
        update_session(sid,workers=states)
    else:
        states=s['workers']
    existing=regular(STATE/'maintenance',False)
    need(existing is None or existing.decode().strip() == sid, '另一个迁移事务占用维护状态')
    atomic(STATE/'maintenance',(sid+'\n').encode())
    for u in states:
        atomic(f'{UNIT}/{u}.d/90-qianyi-hold.conf',f'[Unit]\nConditionPathExists=!{STATE}/maintenance\n'.encode(),0o644)
    systemctl('daemon-reload')
    systemctl('stop',*TIMERS)
    # Never SIGKILL a quota save/reset midway. Let oneshots finish naturally.
    deadline=time.monotonic()+120
    for u in WORKERS+['portbw-restore.service']:
        if u not in states:
            continue
        while active(u) in ('active','activating','deactivating'):
            need(time.monotonic() < deadline, f'{u} 未自然结束，保留维护状态')
            time.sleep(.2)


def stop_bandwidth_worker():
    # Caller holds manager.lock, so no apply transaction can be interrupted.
    if Path('/usr/local/lib/portbw/portbw.py').exists():
        systemctl('stop','portbw-watch.service')


def resume_workers(sid):
    s=session(sid)
    for u in s.get('workers',{}):
        Path(f'{UNIT}/{u}.d/90-qianyi-hold.conf').unlink(missing_ok=True)
    p=STATE/'maintenance'
    if p.exists():
        need(p.read_text().strip() == sid, '维护状态归属异常')
        p.unlink()
    systemctl('daemon-reload')
    for u,state in s.get('workers',{}).items():
        if (u in TIMERS or u == 'portbw-watch.service') and state in ('active','activating'):
            systemctl('start',u)


def fence_ports():
    ports=set()
    for p in (STATE/'sessions').glob('*/state.json'):
        s=read_json(p)
        if s.get('phase') in ('FREEZING','SEALED','TRANSFERRING','OPEN_UNCERTAIN','RETIRED','STAGING','READY','ABORTING'):
            ports.update(int(n['meta']['PORT']) for n in s.get('nodes',[]))
    return ports


def sync_fence(extra=()):
    ports=fence_ports() | set(extra)
    rows=nft_rows()
    present=any(x.get('table',{}).get('name') == 'qianyi_fence' for x in rows)
    # An ownership marker prevents adoption of a same-named foreign table.
    if present:
        table=next(x['table'] for x in rows if x.get('table',{}).get('name') == 'qianyi_fence')
        need(table.get('comment') == 'qianyi-owned-v1', '未知 qianyi_fence 表')
    script='delete table inet qianyi_fence\n' if present else ''
    if ports:
        script += 'add table inet qianyi_fence { comment "qianyi-owned-v1"; }\n'
        script += 'add chain inet qianyi_fence input { type filter hook input priority -310; policy accept; }\n'
        script += 'add chain inet qianyi_fence output { type filter hook output priority -310; policy accept; }\n'
        for p in sorted(ports):
            script += f'add rule inet qianyi_fence input tcp dport {p} drop\nadd rule inet qianyi_fence output tcp sport {p} drop\n'
    if script:
        nft(script)  # one atomic transaction, never flush other tables


def restore_quota_ip(nodes, due=False):
    for n in nodes:
        m=n['meta']; p=m['PORT']; paths=node_paths(m['TAG'],p)
        if n.get('quota'):
            q=apply_due(n['quota'],int(time.time())) if due else n['quota']
            atomic(paths['quota'],env_bytes(q))
            library('vr_pq_restore_one '+shlex.quote(paths['quota']))
        if n.get('iplimit'):
            atomic(paths['iplimit'],env_bytes(n['iplimit']))
            library('vr_il_restore_one '+shlex.quote(paths['iplimit']))
        else:
            library('vr_il_apply_family_guard '+p+' 4')


def verify_protection(nodes):
    rows=nft_rows()
    for n in nodes:
        p=n['meta']['PORT']
        if n.get('quota'):
            q=metadata(regular(node_paths(n['meta']['TAG'],p)['quota']))
            quota_live(q,rows)
        check='vr_il_state ' if n.get('iplimit') else 'vr_il_family_guard_state '
        need(library(check+p) == 'active', f'{p} IP 防护未就绪')
    bandwidth(nodes,rows)


def apply_pause(port):
    name=f'pause_vless_{port}'
    tables={x['table']['name'] for x in nft_rows() if 'table' in x}
    if name not in tables:
        nft(f'''add table inet {name}
add chain inet {name} input {{ type filter hook input priority -20; policy accept; }}
add rule inet {name} input iifname != "lo" tcp dport {port} reject with tcp reset
add rule inet {name} input iifname != "lo" udp dport {port} drop
''')
    atomic(STATE/'pauses'/str(port),b'paused\n')


def apply_restrictions(nodes):
    rows=nft_rows()
    tables={x['table']['name'] for x in rows if 'table' in x}
    current=extract_restrictions(rows,{int(n['meta']['PORT']) for n in nodes})
    script=''
    any_bans=any(n['restrictions']['bans'] for n in nodes)
    if any_bans and 'jsh_cidrban' not in tables:
        script='add table inet jsh_cidrban\nadd chain inet jsh_cidrban pre { type filter hook prerouting priority -150; policy accept; }\n'
    for n in nodes:
        p=int(n['meta']['PORT'])
        if n['restrictions']['paused']:
            apply_pause(p)
        for addr in n['restrictions']['bans']:
            addr=str(ipaddress.IPv4Network(addr,strict=True))
            if addr not in current[p]['bans']:
                script += f'add rule inet jsh_cidrban pre ip saddr {addr} meta l4proto {{ tcp, udp }} th dport {p} counter drop comment "jshcidr:{p}:{addr}"\n'
    if script:
        nft(script)
    if any_bans:
        # Serialize just the target's current table, after merging semantic entries.
        atomic('/etc/jsh-cidrban.nft',run(['nft','list','table','inet','jsh_cidrban']).stdout)
        service='[Unit]\nDescription=Jieshu CIDR port blacklist\nAfter=nftables.service\nBefore=network.target\n[Service]\nType=oneshot\nExecStart=/usr/sbin/nft -f /etc/jsh-cidrban.nft\n[Install]\nWantedBy=multi-user.target\n'
        old=regular(f'{UNIT}/jsh-cidrban.service',False)
        need(old is None or old.decode() == service, '未知黑名单启动服务，拒绝覆盖')
        atomic(f'{UNIT}/jsh-cidrban.service',service.encode(),0o644)
        systemctl('daemon-reload')
        systemctl('enable','jsh-cidrban.service')


def install_bandwidth(snapshot):
    if not snapshot['bandwidth']:
        return
    mod=load_module('/usr/local/lib/portbw/portbw.py','_qianyi_portbw')
    config=mod.cfg()
    mapping=read_json(STATE/'boot-origins.json') if (STATE/'boot-origins.json').exists() else {}
    mapping[boot_id()]=time.time()-boottime()
    save(STATE/'boot-origins.json',mapping)
    for p,rec in snapshot['bandwidth'].items():
        rec=rebase_bandwidth(rec,snapshot['boot_origin'],time.time(),boottime(),boot_id())
        mod.validate_record(int(p),rec)
        mod.volatile_clear(int(p))
        mod.write_json(mod.port_file(int(p)),rec)
        # Apply only this node; never repair/flush the entire NIC.
        with contextlib.redirect_stdout(sys.stderr):
            mod.finish_apply(int(p),rec,config)


def freeze(sid):
    s=session(sid); path=session_path(sid)
    if (path/'snapshot.json').exists():
        need(s['phase'] in ('SEALED','TRANSFERRING','OPEN_UNCERTAIN'), '旧源快照不能重新使用')
        return read_json(path/'snapshot.json')
    if s['phase'] == 'PREPARED':
        fresh=probe('source')
        # Target preflight is repeated for newly created/modified nodes before maintenance.
        target=remote(s['ssh'],'probe-target',fresh)
        need(target['info']['machine'] == s['target_machine'], '目标机器身份发生变化')
        remote(s['ssh'],'refresh',{'sid':sid,'manifest':fresh})
        update_session(sid,phase='FREEZING',nodes=fresh['nodes'],info=fresh['info'],protected=fresh['protected'])
        s=session(sid)
    need(s['phase'] == 'FREEZING', '源事务状态不允许冻结')
    pause_workers(sid)
    hold_nodes(sid,s['nodes'])
    with locks():
        stop_bandwidth_worker()
        sync_fence()
        need({p.stem for p in Path(VR+'/temp').glob('*.env')} == {n['meta']['TAG'] for n in s['nodes']},
             '预检后节点集合发生变化，保持冻结；请按恢复说明处理')
        for n in s['nodes']:
            systemctl('stop',n['meta']['TAG']+'.service')
            need(active(n['meta']['TAG']+'.service') in ('inactive','failed'), '源节点没有停止')
        need(not (listening() & {int(n['meta']['PORT']) for n in s['nodes']}), '源端口仍有监听')
        intent_path=path/'settlement.json'
        if intent_path.exists():
            snap=read_json(intent_path)
        else:
            need(boot_id() == s['info']['boot'], '冻结结算前发生重启，内核计数已不可证明；保持关闭，需人工恢复计量依据')
            # Exact byte comparison excludes concurrent manual mutation between preflight
            # and the acquired writer locks. Background usage is deliberately allowed.
            nodes=copy.deepcopy(s['nodes'])
            for n in nodes:
                paths=node_paths(n['meta']['TAG'],n['meta']['PORT'])
                for k in ('config','url','unit'):
                    need(regular(paths[k]).decode() == n[k], '维护前节点配置发生变化，请重新预检')
                current=metadata(regular(paths['meta']))
                stable={k:v for k,v in current.items() if not k.startswith('WATCHDOG_')}
                expected={k:v for k,v in n['meta'].items() if not k.startswith('WATCHDOG_')}
                need(stable == expected, '维护前节点元数据发生变化')
                n['meta']=current
                for k in ('quota','iplimit'):
                    raw=regular(paths[k],False)
                    n[k]=metadata(raw) if raw else None
                validate_node(n)
            rows=nft_rows(); now=int(time.time())
            restrictions=extract_restrictions(rows,{int(n['meta']['PORT']) for n in nodes})
            for n in nodes:
                if n['quota']:
                    n['quota']=settled_quota(n['quota'],quota_live(n['quota'],rows),now)
                n['restrictions']=restrictions[int(n['meta']['PORT'])]
                n['restrictions']['paused'] |= n['disabled']
            snap={'schema':1,'sid':sid,'source_machine':machine_id(),'target_machine':s['target_machine'],
                  'created':now,'info':s['info'],'nodes':nodes,'bandwidth':bandwidth(nodes,rows),
                  'boot_origin':time.time()-boottime()}
            save(intent_path,snap)  # durable before resetting any kernel generation
        restore_quota_ip(snap['nodes'])
        check_preserved(s['protected'])
        save(path/'snapshot.json',snap)
        update_session(sid,phase='SEALED',snapshot_sha=digest(encoded(snap)),nodes=snap['nodes'])
        return snap


def validate_snapshot(snap, s):
    need(snap.get('schema') == 1 and snap.get('sid') == s['sid'], '快照事务编号/格式错误')
    need(snap['source_machine'] == s['source_machine'] and snap['target_machine'] == machine_id(), '快照机器身份不匹配')
    need(digest(encoded(snap)) == s.get('snapshot_sha',digest(encoded(snap))), '同一事务收到不同快照，拒绝重放')
    need(snap['nodes'] and len({n['meta']['PORT'] for n in snap['nodes']}) == len(snap['nodes']), '快照节点端口重复或为空')
    for n in snap['nodes']:
        validate_node(n)
        r=n['restrictions']
        need(type(r['paused']) is bool, '暂停字段非法')
        for addr in r['bans']:
            ipaddress.IPv4Network(addr,strict=True)
    need(set(snap['bandwidth']) <= {n['meta']['PORT'] for n in snap['nodes']}, '快照限速端口越界')


def target_prepare(request):
    sid=request['sid']; path=session_path(sid)
    need(not (path/'state.json').exists(), '目标已存在该事务')
    for p in (STATE/'sessions').glob('*/state.json'):
        need(read_json(p).get('phase') not in ('PREPARED','STAGING','READY'), '目标有未完成事务')
    manifest=request['manifest']
    checked=probe('target',manifest)
    update_session(sid,sid=sid,role='target',phase='PREPARED',source_machine=manifest['info']['machine'],
                   target_machine=machine_id(),nodes=manifest['nodes'],protected=checked['protected'])
    return {'sid':sid,'machine':machine_id(),'phase':'PREPARED'}


def target_refresh(request):
    sid=request['sid']; s=session(sid)
    need(s['phase'] == 'PREPARED', '目标不允许刷新准备信息')
    manifest=request['manifest']; probe('target',manifest)
    need(manifest['info']['machine'] == s['source_machine'], '源机身份发生变化')
    update_session(sid,nodes=manifest['nodes'])
    return {'phase':'PREPARED'}


def import_write(sid, path, data, mode=0o600):
    s=session(sid); known=s.get('writes',{})
    old=regular(path,False)
    h=digest(data)
    need(old is None or digest(old) in (known.get(path),h), f'导入路径被未知数据修改：{path}')
    known[path]=h
    update_session(sid,writes=known)  # write-ahead ownership journal
    atomic(path,data,mode)


def target_stage(snap):
    sid=snap['sid']; s=session(sid)
    need(s['role'] == 'target' and s['phase'] in ('PREPARED','STAGING','READY'), '目标已开放、撤销或处于未知状态；禁止旧快照覆盖')
    validate_snapshot(snap,s)
    if s['phase'] == 'READY':
        verify_target(sid)
        return {'phase':'READY','snapshot_sha':s['snapshot_sha']}
    if s['phase'] == 'PREPARED':
        with locks():
            check_empty(snap['nodes'],nft_rows())
        save(session_path(sid)/'snapshot.json',snap)
        update_session(sid,phase='STAGING',snapshot_sha=digest(encoded(snap)),nodes=snap['nodes'])
    pause_workers(sid)
    hold_nodes(sid,snap['nodes'])
    with locks():
        stop_bandwidth_worker()
        sync_fence()
        check_preserved(s['protected'])
        for n in snap['nodes']:
            m=n['meta']; paths=node_paths(m['TAG'],m['PORT'])
            check_wg(m)
            import_write(sid,paths['meta'],env_bytes(m))
            for k in ('config','url','unit'):
                import_write(sid,paths[k],n[k].encode(),0o644 if k == 'unit' else 0o600)
            for k in ('quota','iplimit'):
                if n.get(k):
                    record=apply_due(n[k],int(time.time())) if k == 'quota' else n[k]
                    import_write(sid,paths[k],env_bytes(record))
            output(['/usr/local/bin/xray','run','-test','-config',paths['config']])
        restore_quota_ip(snap['nodes'],due=True)
        apply_restrictions(snap['nodes'])
        install_bandwidth(snap)
        verify_protection(snap['nodes'])
        check_preserved(s['protected'])
        update_session(sid,phase='READY')
    # The gate takes quota/IP locks itself; never start systemd nodes under them.
    release_nodes(snap['nodes'])
    systemctl('start','qianyi-boot.service')
    for n in snap['nodes']:
        if int(n['meta']['EXPIRE_EPOCH']) <= int(time.time()):
            continue
        unit=n['meta']['TAG']+'.service'
        systemctl('enable',unit)
        systemctl('start',unit)
    verify_target(sid)
    return {'phase':'READY','snapshot_sha':digest(encoded(snap))}


def verify_target(sid):
    s=session(sid)
    need(s['role'] == 'target' and s['phase'] in ('READY','OPEN'), '目标未进入可验证阶段')
    snap=read_json(session_path(sid)/'snapshot.json')
    check_preserved(s['protected'])
    current=[]
    for n in snap['nodes']:
        m=n['meta']; paths=node_paths(m['TAG'],m['PORT'])
        if int(m['EXPIRE_EPOCH']) <= int(time.time()):
            continue
        for k in ('config','url','unit'):
            need(regular(paths[k]).decode() == n[k], f'{m["TAG"]} 认证配置或链接发生变化')
        actual=copy.deepcopy(n)
        actual['meta']=metadata(regular(paths['meta']))
        for k in ('quota','iplimit'):
            raw=regular(paths[k],False)
            actual[k]=metadata(raw) if raw else None
        validate_node(actual)
        check_wg(m)
        need(active(m['TAG']+'.service') == 'active', f'{m["TAG"]} 服务未运行')
        current.append(actual)
    listeners=listening()
    need(all(int(n['meta']['PORT']) in listeners for n in current), '目标有节点尚未监听')
    with locks():
        verify_protection(current)
        restrictions=extract_restrictions(nft_rows(),{int(n['meta']['PORT']) for n in current})
        for n in current:
            actual=restrictions[int(n['meta']['PORT'])]
            expected=n['restrictions']
            need(not expected['paused'] or actual['paused'], '端口暂停未恢复')
            need(set(expected['bans']) <= set(actual['bans']), '来源黑名单未恢复')
    return {'phase':s['phase'],'nodes':len(current),'expired':len(snap['nodes'])-len(current),
            'snapshot_sha':s['snapshot_sha'],'machine':machine_id()}


def target_open(sid):
    s=session(sid)
    need(s['phase'] in ('READY','OPEN'), '目标未就绪或已撤销')
    if s['phase'] == 'READY':
        verify_target(sid)
        # This is the irreversible commit point. A lost response MUST NOT make
        # the source resume. Retry only removes fences/resumes tasks, never imports.
        update_session(sid,phase='OPEN',opened=int(time.time()))
    sync_fence()
    resume_workers(sid)
    return {'phase':'OPEN','machine':machine_id(),'snapshot_sha':session(sid)['snapshot_sha']}


def retire_source(sid):
    s=session(sid)
    need(s['phase'] in ('SEALED','TRANSFERRING','OPEN_UNCERTAIN','RETIRED'), '源机状态无法退休')
    pause_workers(sid)
    with locks():
        stop_bandwidth_worker()
        for n in s['nodes']:
            tag=n['meta']['TAG']; p=n['meta']['PORT']
            need(active(tag+'.service') not in ('active','activating'), '源机仍运行待迁移节点')
            systemctl('disable',tag+'.service',check=False)
            # Move, do not destroy: source snapshots and originals remain mode 0600.
            for key,filename in node_paths(tag,p).items():
                src=Path(filename)
                dst=session_path(sid)/'originals'/tag/key
                if src.exists():
                    need(not dst.exists(), '归档路径冲突，拒绝覆盖恢复数据')
                    dst.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                    os.replace(src,dst)
            # Kernel guards may be removed only while the independent fence remains.
            library('vr_pq_delete_managed_port '+p+'\nvr_il_delete_managed_port '+p)
        update_session(sid,phase='RETIRED')
        sync_fence()
    systemctl('daemon-reload')
    resume_workers(sid)


def target_abort(sid):
    s=session(sid)
    need(s['role'] == 'target' and s['phase'] in ('PREPARED','STAGING','READY','ABORTING','ABORTED'),
         '目标可能已承载新流量，禁止回到旧余额；必须以目标最新状态重新迁移')
    if s['phase'] == 'ABORTED':
        return {'phase':'ABORTED','machine':machine_id()}
    update_session(sid,phase='ABORTING')
    pause_workers(sid)
    hold_nodes(sid,s['nodes'])
    with locks():
        stop_bandwidth_worker(); sync_fence()
        for n in s['nodes']:
            unit=n['meta']['TAG']+'.service'
            systemctl('stop',unit,check=False)
            need(active(unit) in ('inactive','failed'), '目标节点尚未停止，无法撤销')
        need(not (listening() & {int(n['meta']['PORT']) for n in s['nodes']}), '目标有残留监听，不能允许源机恢复')
        # Do not erase partial imports. ABORTED is a permanent tombstone. The
        # target needs cleanup/reinstallation before reuse as an empty standby.
        update_session(sid,phase='ABORTED')
    # Keep node holds and imported data. Resume shared workers only on a pristine
    # PREPARED target; partial imports stay quarantined for explicit repair.
    return {'phase':'ABORTED','machine':machine_id()}


def source_abort(sid):
    s=session(sid)
    need(s['role'] == 'source' and s['phase'] in ('PREPARED','FREEZING','SEALED','TRANSFERRING'),
         '已开放或结果不确定时禁止旧余额回退；先查目标状态')
    result=remote(s['ssh'],'abort-target',{'sid':sid})
    need(result['phase'] == 'ABORTED' and result['machine'] == s['target_machine'], '没有取得目标撤销确认')
    if s['phase'] == 'PREPARED':
        update_session(sid,phase='ABORTED')
        return
    # Complete settlement first. No source listener is released without proof.
    snap=freeze(sid)
    with locks():
        restore_quota_ip(snap['nodes'],due=True)
        verify_protection(snap['nodes'])
    update_session(sid,phase='RESUMED')
    release_nodes(snap['nodes'])
    for n in snap['nodes']:
        if int(n['meta']['EXPIRE_EPOCH']) > time.time() and not n['disabled']:
            systemctl('start',n['meta']['TAG']+'.service')
    sync_fence()
    resume_workers(sid)


def gate(tag):
    need(TAG_RE.fullmatch(tag), '非法节点标签')
    mapping=owners()
    need(tag in mapping, '节点没有迁移归属记录')
    s=session(mapping[tag])
    need(s['phase'] in ('READY','OPEN','RESUMED'), '节点处于迁移冻结状态')
    m=metadata(regular(f'{VR}/temp/{tag}.env'))
    need(int(m['EXPIRE_EPOCH']) > time.time(), '节点已到期')
    check_wg(m)  # no wg guard/healthcheck/network reconfiguration
    p=m['PORT']
    with locks(readonly=True):
        n={'meta':m,'quota':metadata(regular(f'{VR}/quota/{p}.env')) if m.get('PQ_LIMIT_BYTES') else None,
           'iplimit':metadata(regular(f'{VR}/iplimit/{p}.env')) if int(m['IP_LIMIT']) else None}
        verify_protection([n])


def boot_restore():
    with locks():
        sync_fence()
        for p in (STATE/'pauses').glob('*'):
            port=uint(p.name,'暂停端口',65535)
            apply_pause(port)
        path=STATE/'boot-origins.json'
        origins=read_json(path) if path.exists() else {}
        if Path('/usr/local/lib/portbw/portbw.py').exists():
            mod=load_module('/usr/local/lib/portbw/portbw.py','_qianyi_portbw')
            managed={int(n['meta']['PORT']) for p in (STATE/'sessions').glob('*/state.json')
                     for n in read_json(p).get('nodes',[])}
            for p,rec in mod.records().items():
                if p not in managed or 'auto' not in rec or rec['runtime']['boot_id'] == boot_id():
                    continue
                old=rec['runtime']['boot_id']
                need(old in origins, '缺失自动限速时钟映射；拒绝提前解除限制')
                prefs=rec.get('tc_prefs')
                rec=rebase_bandwidth(rec,origins[old],time.time(),boottime(),boot_id())
                if prefs:
                    rec['tc_prefs']=prefs  # same machine reboot, same owned slots
                mod.validate_record(p,rec); mod.volatile_clear(p); mod.write_json(mod.port_file(p),rec)
        origins[boot_id()]=time.time()-boottime()
        save(path,origins)


def ssh_args(settings, master=False):
    host=str(ipaddress.IPv4Address(settings['host']))
    need(ipaddress.IPv4Address(host).is_global, '管理地址必须是服务器实际公网 IPv4')
    port=uint(settings['port'],'SSH 端口',65535)
    need(port > 0, 'SSH 端口非法')
    args=['ssh','-p',str(port),'-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=15',
          '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3','-o','LogLevel=ERROR']
    if settings.get('identity'):
        args += ['-i',settings['identity']]
    if settings.get('control'):
        args += ['-o','ControlPath='+settings['control']]
    if master:
        args += ['-M','-N','-f','-o','ControlPersist=1800']
    return args+['root@'+host]


def remote(settings, action, payload, bootstrap=False):
    need(re.fullmatch('[a-z-]+',action), '远程动作非法')
    if bootstrap:
        code=base64.b64encode(zlib.compress(program_bytes(),9)).decode()
        py=("import base64,zlib,sys;__file__="+repr(PROGRAM)+";sys.argv=['qianyi','agent',"+repr(action)+
            "];exec(compile(zlib.decompress(base64.b64decode("+repr(code)+")),__file__,'exec'))")
        command='python3 -c '+shlex.quote(py)
    else:
        command='python3 '+PROGRAM+' agent '+action
    # Inherit stderr only at the SSH layer for normal authentication/host-key
    # diagnostics; remote program messages contain no node credentials.
    r=run(ssh_args(settings)+[command],data=encoded(payload),timeout=900,check=False)
    if r.returncode:
        raise Error(f'SSH/目标动作 {action} 失败（{r.returncode}），状态已保留；用 status/resume 检查')
    try:
        reply=json.loads(r.stdout)
    except ValueError as e:
        raise Error('目标响应不是有效协议消息，交接结果视为不确定') from e
    need(isinstance(reply,dict) and reply.get('ok') is True, '目标没有确认动作成功')
    return reply['result']


def public_status(sid):
    s=session(sid)
    return {k:s[k] for k in ('sid','role','phase','source_machine','target_machine','snapshot_sha','updated','opened','confirmed') if k in s} | {
        'nodes':len(s.get('nodes',[])), 'last_error':s.get('last_error','')}


def agent_action(action,request):
    need(os.geteuid() == 0, '远端需要 root')
    if action == 'probe-target':
        return probe('target',request)
    if action == 'install':
        raw=base64.b64decode(request['program'],validate=True)
        need(digest(raw) == request['sha'], '程序传输摘要不一致')
        install_program(raw)
        return {'installed':True,'sha':request['sha']}
    if action == 'status':
        return public_status(request['sid'])
    with locks(['/run/qianyi-transaction.lock']):
        if action == 'prepare':
            return target_prepare(request)
        if action == 'refresh':
            return target_refresh(request)
        if action == 'stage':
            return target_stage(request)
        if action == 'open':
            return target_open(request['sid'])
        if action == 'verify':
            return verify_target(request['sid'])
        if action == 'abort-target':
            return target_abort(request['sid'])
    raise Error('未知远端动作')


def preflight(settings):
    source=probe('source')
    need(int(settings['port']) not in {int(n['meta']['PORT']) for n in source['nodes']}, 'SSH 管理端口与用户端口重叠')
    target=remote(settings,'probe-target',source,bootstrap=True)
    report={'nodes':len(source['nodes']), 'nat':sum(n['meta'].get('LANDING') == 'nat' for n in source['nodes']),
            'source':source['info']['machine'],'target':target['info']['machine'],
            'upstream':PROFILE['commit'],'xray':source['info']['xray']}
    return source,target,report


def prepare(settings):
    source,target,report=preflight(settings)
    sid=uuid.uuid4().hex
    install_program()
    program=program_bytes()
    remote(settings,'install',{'program':base64.b64encode(program).decode(),'sha':digest(program)},bootstrap=True)
    result=remote(settings,'prepare',{'sid':sid,'manifest':source})
    need(result['machine'] == target['info']['machine'], '准备后目标身份发生变化')
    update_session(sid,sid=sid,role='source',phase='PREPARED',ssh=settings,source_machine=machine_id(),
                   target_machine=target['info']['machine'],nodes=source['nodes'])
    print(f'准备完成：{sid}；{report["nodes"]} 个节点。尚未停止源节点。')
    print(f'开始交接：python3 {PROGRAM} cutover {sid}')
    return sid


def worker(sid):
    try:
        with locks(['/run/qianyi-transaction.lock']):
            s=session(sid)
            need(s['role'] == 'source', '必须在当前源机执行')
            if s['phase'] == 'RETIRED':
                return
            if s['phase'] == 'OPEN_UNCERTAIN':
                status=remote(s['ssh'],'status',{'sid':sid})
                need(status['target_machine'] == s['target_machine'], '远端身份不符')
                if status['phase'] == 'OPEN':
                    remote(s['ssh'],'open',{'sid':sid})
                    retire_source(sid)
                    return
                need(status['phase'] == 'READY', '目标开放结果无法确认，保持源机冻结')
                remote(s['ssh'],'open',{'sid':sid})
                retire_source(sid)
                return
            snap=freeze(sid)
            update_session(sid,phase='TRANSFERRING')
            result=remote(s['ssh'],'stage',snap)
            need(result['phase'] == 'READY' and result['snapshot_sha'] == digest(encoded(snap)), '目标尚未确认同一快照就绪')
            update_session(sid,phase='OPEN_UNCERTAIN')
            result=remote(s['ssh'],'open',{'sid':sid})
            need(result['phase'] == 'OPEN' and result['machine'] == s['target_machine'], '目标接管确认失败')
            retire_source(sid)
            update_session(sid,last_error='')
    except Exception as e:
        message=str(e) if isinstance(e,Error) else f'内部检查失败：{type(e).__name__}'
        update_session(sid,last_error=message)
        print(message, file=sys.stderr)
        raise


def launch(sid):
    s=session(sid)
    need(s['role'] == 'source' and s['phase'] not in ('ABORTED','RESUMED','RETIRED'), '该事务不允许交接/重试')
    control=Path('/run/qianyi')
    control.mkdir(mode=0o700,exist_ok=True)
    need(control.stat().st_uid == 0 and not control.stat().st_mode & 0o077 and not control.is_symlink(), 'SSH 控制目录权限不安全')
    settings=dict(s['ssh'],control=str(control/(sid+'.sock')))
    # Authentication happens in the user's foreground terminal; no password or
    # private key is copied into the job. The worker reuses a root-only SSH socket.
    args=ssh_args(settings,master=True)
    proc=subprocess.run(args,check=False)
    need(proc.returncode == 0, 'SSH 认证失败；请先用 IP 正常 SSH，核对主机密钥')
    update_session(sid,ssh=settings)
    unit='qianyi-transfer-'+sid
    need(active(unit+'.service') not in ('active','activating'), '交接任务已运行')
    systemctl('reset-failed',unit+'.service',check=False)
    args=['systemd-run','--unit',unit,'--collect','--property=Type=exec','--property=UMask=0077',
          '--property=KillMode=control-group','/usr/bin/python3',PROGRAM,'worker',sid]
    output(args)
    print(f'交接已在 systemd 后台运行，SSH 终端断开不会停止任务。事务：{sid}')
    print(f'查询：python3 {PROGRAM} status {sid}')


def main():
    parser=argparse.ArgumentParser(description='jieshu 临时节点迁移；请先阅读 README 和 VPS 验收说明')
    sub=parser.add_subparsers(dest='action',required=True)
    for name in ('preflight','prepare','migrate'):
        p=sub.add_parser(name)
        p.add_argument('--target',help='目标服务器实际公网 IPv4')
        p.add_argument('--ssh-port',type=int,default=22)
        p.add_argument('--identity',help='本机 SSH 私钥路径；也可用 ssh-agent 或正常密码认证')
    for name in ('cutover','resume','abort','verify','confirm','worker'):
        p=sub.add_parser(name); p.add_argument('sid')
    p=sub.add_parser('status'); p.add_argument('sid',nargs='?')
    p=sub.add_parser('gate'); p.add_argument('tag')
    sub.add_parser('boot')
    p=sub.add_parser('agent'); p.add_argument('operation')
    p=sub.add_parser('unpause'); p.add_argument('port',type=int)
    p=sub.add_parser('build'); p.add_argument('output')
    args=parser.parse_args()
    if args.action == 'build':
        atomic(args.output,program_bytes(),0o700)
        print('已生成独立程序（含固定兼容性清单）')
        return
    need(os.geteuid() == 0, '请使用 root 运行')
    os.umask(0o077)
    if args.action == 'agent':
        req=json.loads(sys.stdin.buffer.read(64*1024*1024))
        result=agent_action(args.operation,req)
        print(json.dumps({'ok':True,'result':result},ensure_ascii=False))
    elif args.action in ('preflight','prepare','migrate'):
        host=args.target or input('目标服务器公网 IPv4：').strip()
        settings={'host':host,'port':args.ssh_port,'identity':args.identity}
        if args.action == 'preflight':
            _,_,report=preflight(settings)
            print(json.dumps(report,ensure_ascii=False,indent=2))
            print('只读预检通过。尚未修改业务状态，也未生成可导入快照。')
        else:
            with locks(['/run/qianyi-transaction.lock']):
                sid=prepare(settings)
            if args.action == 'migrate':
                launch(sid)
    elif args.action in ('cutover','resume'):
        launch(args.sid)
    elif args.action == 'worker':
        worker(args.sid)
    elif args.action == 'abort':
        need(active('qianyi-transfer-'+args.sid+'.service') not in ('active','activating'), '交接任务仍在运行')
        with locks(['/run/qianyi-transaction.lock']):
            source_abort(args.sid)
        print('目标已撤销；源机按最终结算状态恢复（已到期节点不会恢复）。')
    elif args.action in ('verify','confirm'):
        s=session(args.sid)
        result=remote(s['ssh'],'verify',{'sid':args.sid}) if s['role'] == 'source' else verify_target(args.sid)
        if args.action == 'confirm':
            need(result['phase'] == 'OPEN', '目标尚未开放')
            update_session(args.sid,confirmed=int(time.time()))
        print(json.dumps(result,ensure_ascii=False,indent=2))
        if args.action == 'confirm':
            print('已记录你的外部连通性确认。旧机重装由你自行完成。')
    elif args.action == 'status':
        ids=[args.sid] if args.sid else [p.parent.name for p in (STATE/'sessions').glob('*/state.json')]
        for sid in ids:
            s=session(sid); print(json.dumps(public_status(sid),ensure_ascii=False,indent=2))
            if s['role'] == 'source' and s['phase'] == 'RETIRED':
                print('目标已接管、源临时节点已冻结并归档。现在可以手工将业务域名 A 记录改为目标公网 IP；请从外部客户端使用原链接验证，再 confirm。')
            elif s['phase'] == 'OPEN_UNCERTAIN':
                print('目标可能已使用新流量；禁止源机回退旧余额。请 resume 查询并完成交接。')
            elif s['phase'] in ('FREEZING','SEALED','TRANSFERRING'):
                print('源机保持冻结；可以 resume。不要手工启动节点或删除迁移状态。')
    elif args.action == 'gate':
        gate(args.tag)
    elif args.action == 'boot':
        boot_restore()
    elif args.action == 'unpause':
        p=uint(args.port,'端口',65535); need(p != 443 and p > 0,'不能操作 443')
        need((STATE/'pauses'/str(p)).exists(), '该端口不是 qianyi 持久暂停记录')
        with locks(['/run/qianyi-transaction.lock']):
            nft(f'delete table inet pause_vless_{p}\n')
            (STATE/'pauses'/str(p)).unlink()
        print(f'{p} 已解除迁入的持久暂停；配额/IP/黑名单保持原规则。')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('操作中断；先 status，再 resume；不要手工恢复旧余额。',file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        message=str(exc) if isinstance(exc,Error) else f'检查失败：{type(exc).__name__}；没有放行未验证节点'
        print(message,file=sys.stderr)
        sys.exit(1)
