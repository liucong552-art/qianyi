#!/usr/bin/env python3
"""Real nftables tests ONLY in an isolated throwaway network namespace.
CI runs this inside a Debian 13 container with NET_ADMIN, never on a VPS host.
"""
import contextlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
from unittest.mock import patch
from test_qianyi import q,node,SID

if os.environ.get('QIANYI_DISPOSABLE_NETNS') != '1':
    raise SystemExit('Run only in the disposable CI network namespace; no production host.')

n=node();p=n['meta']['PORT'];left=n['quota']['LIMIT_BYTES']
script=f'''
add table inet vr_pq
add chain inet vr_pq pq_input {{ type filter hook input priority 0; policy accept; }}
add chain inet vr_pq pq_output {{ type filter hook output priority 0; policy accept; }}
add counter inet vr_pq vr_pq_in_{p}
add counter inet vr_pq vr_pq_out_{p}
add quota inet vr_pq vr_pq_q_{p} {{ over {left} bytes used 0 bytes }}
add rule inet vr_pq pq_input tcp dport {p} quota name "vr_pq_q_{p}" drop comment "vr-pq-drop-in-{p}"
add rule inet vr_pq pq_input tcp dport {p} counter name "vr_pq_in_{p}" comment "vr-pq-count-in-{p}"
add rule inet vr_pq pq_output tcp sport {p} quota name "vr_pq_q_{p}" drop comment "vr-pq-drop-out-{p}"
add rule inet vr_pq pq_output tcp sport {p} counter name "vr_pq_out_{p}" comment "vr-pq-count-out-{p}"
add table inet vr_iplimit
add chain inet vr_iplimit il_input {{ type filter hook input priority -10; policy accept; }}
add rule inet vr_iplimit il_input meta nfproto ipv6 tcp dport {p} drop comment "vr-il-family-{p}"
add set inet vr_iplimit vr_il4_{p} {{ type ipv4_addr; size 2; flags timeout,dynamic; timeout 120s; }}
add rule inet vr_iplimit il_input meta nfproto ipv4 tcp dport {p} ip saddr @vr_il4_{p} update @vr_il4_{p} {{ ip saddr timeout 120s }} accept comment "vr-il-refresh-{p}"
add rule inet vr_iplimit il_input meta nfproto ipv4 tcp dport {p} add @vr_il4_{p} {{ ip saddr timeout 120s }} accept comment "vr-il-claim-{p}"
add rule inet vr_iplimit il_input meta nfproto ipv4 tcp dport {p} drop comment "vr-il-drop-{p}"
add table inet jsh_cidrban
add chain inet jsh_cidrban pre {{ type filter hook prerouting priority -150; policy accept; }}
add rule inet jsh_cidrban pre ip saddr 10.2.0.0/24 meta l4proto {{ tcp, udp }} th dport {p} counter drop comment "jshcidr:{p}:10.2.0.0/24"
'''
subprocess.run(['nft','-f','-'],input=script.encode(),check=True)
rows=q.nft_rows()
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
print(json.dumps({'debian':Path('/etc/debian_version').read_text().strip(),
                  'nft':q.output(['nft','--version']),'counted_bytes':used,
                  'passed':['native quota + live TCP accounting','IPv4 dynamic IP set schema',
                            'CIDR restriction schema','pause schema','atomic migration fence']},indent=2))
