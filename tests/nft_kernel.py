#!/usr/bin/env python3
"""Real nftables tests ONLY in an isolated throwaway network namespace.
CI runs this inside a Debian 13 container with NET_ADMIN, never on a VPS host.
"""
import contextlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
from unittest.mock import patch
from test_qianyi import q,node,SID

if os.environ.get('QIANYI_DISPOSABLE_NETNS') != '1':
    raise SystemExit('Run only in the disposable CI network namespace; no production host.')

# Extract only the pinned libraries; never run either upstream installer.
source=Path('audited-upstream/vless.sh').read_bytes()
assert q.digest(source) == q.PROFILE['sources']['vless.sh']
libraries={'common.sh','quota-lib.sh','iplimit-lib.sh','quota-query.py'}
text=source.decode();extracted=set()
for match in re.finditer(r"^cat >'([^']+)' <<'([^']+)'\n",text,re.M):
    dest,end=match.groups()
    if Path(dest).name not in libraries:continue
    raw=(text[match.end():].split('\n'+end+'\n',1)[0]+'\n').encode()
    assert q.digest(raw) == q.PROFILE['files'][dest]
    q.atomic(dest,raw,0o755);extracted.add(Path(dest).name)
assert extracted == libraries
n=node();p=n['meta']['PORT']
q.atomic(q.node_paths(n['meta']['TAG'],p)['meta'],q.env_bytes(n['meta']))
q.restore_quota_ip([n])
assert q.library('vr_il_state '+p) == 'active'
q.nft(f'''
add table inet jsh_cidrban
add chain inet jsh_cidrban pre {{ type filter hook prerouting priority -150; policy accept; }}
add rule inet jsh_cidrban pre ip saddr 10.2.0.0/24 meta l4proto {{ tcp, udp }} th dport {p} counter drop comment "jshcidr:{p}:10.2.0.0/24"
''')
rows=q.nft_rows()
print('native_ip_expressions='+json.dumps([e['rule']['expr'] for e in rows if e.get('rule',{}).get('table') == 'vr_iplimit']))
q.check_native_tables(rows,[n])
assert q.quota_live(n['quota'],rows) == 0
assert q.extract_restrictions(rows,{int(p)})[int(p)]['bans'] == ['10.2.0.0/24']
server=socket.socket();server.bind(('127.0.0.1',int(p)));server.listen(1)
def echo():
    with server.accept()[0] as conn:
        data=conn.recv(8192);conn.sendall(data)
thread=threading.Thread(target=echo);thread.start()
with socket.create_connection(('127.0.0.1',int(p)),timeout=2) as c:
    c.sendall(b'x'*4096);assert len(c.recv(8192)) > 0
thread.join(timeout=3);assert not thread.is_alive()
used=q.quota_live(n['quota'],q.nft_rows());assert used > 0
# Settle once with native restore and verify that neither the old kernel
# generation nor another round of restore grants extra user credit.
n['quota']=q.settled_quota(n['quota'],used,1500000000)
q.restore_quota_ip([n])
assert q.quota_live(n['quota'],q.nft_rows()) == 0
assert int(n['quota']['SAVED_USED_BYTES']) == 60*1024**3+used
assert int(n['quota']['LIMIT_BYTES']) == 40*1024**3-used
with tempfile.TemporaryDirectory() as d,patch.object(q,'STATE',Path(d)):
    q.update_session(SID,sid=SID,role='source',phase='FREEZING',nodes=[n])
    q.sync_fence()
    try:
        socket.create_connection(('127.0.0.1',int(p)),timeout=.3)
        raise AssertionError('fence did not block')
    except TimeoutError:
        pass
    q.update_session(SID,phase='OPEN')
    q.sync_fence()
    q.apply_pause(int(p))
    assert q.extract_restrictions(q.nft_rows(),{int(p)})[int(p)]['paused']
server.close()
n['quota']=q.settled_quota(n['quota'],int(n['quota']['LIMIT_BYTES']),1500000001)
q.restore_quota_ip([n])
assert q.quota_live(n['quota'],q.nft_rows()) == 0
assert n['quota']['LIMIT_BYTES'] == '0'
print(json.dumps({'debian':Path('/etc/debian_version').read_text().strip(),
                  'nft':q.output(['nft','--version']),'counted_bytes':used,
                  'passed':['pinned upstream libraries + native restore','live TCP accounting + settlement + exhausted guards','IPv4 dynamic IP set schema',
                            'CIDR restriction schema','pause schema','atomic migration fence']},indent=2))
