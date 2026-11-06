#!/usr/bin/env python3
"""Real pinned portbw + nft/tc integration; disposable CI container ONLY."""
import copy
import json
import os
from pathlib import Path
import time
from unittest.mock import patch
from test_qianyi import q, node, auto_record

if os.environ.get('QIANYI_DISPOSABLE_NETNS') != '1':
    raise SystemExit('Only run in the disposable CI network namespace.')

raw=Path('audited-upstream/portbw.py').read_bytes()
path='/usr/local/lib/portbw/portbw.py'
assert q.digest(raw) == q.PROFILE['files'][path]
q.atomic(path,raw,0o755)
mod=q.load_module(path,'_qianyi_native_portbw')
q.save('/etc/portbw/config.json',{'iface':'eth0','tc_enabled':True,'version':2})
for name,body in mod.units().items():q.atomic(Path(q.UNIT)/name,body.encode(),0o644)
mod.ensure_base()
config=mod.cfg()
main={'port':443,'up':250000,'down':250000,'pending':True,'deleting':False}
mod.write_json(mod.port_file(443),main)
mod.finish_apply(443,main,config)
main_bytes=mod.port_file(443).read_bytes()
root_before=[(r['kind'],r['handle']) for r in mod.tc_qdiscs('eth0') if r.get('root')]

def service_status(*args,**kw):
    if args[0] == 'is-enabled':return 'enabled'
    if args[:2] == ('show','-p') and args[2] == 'DropInPaths':return ''
    raise AssertionError('unexpected systemd operation in nft/tc-only test')

nodes=[node(40002),node(40003)]
with patch.object(q,'systemctl',side_effect=service_status):
    assert q.bandwidth(nodes,q.nft_rows(),target=True) == {}
    static={'port':40002,'up':1250000,'down':2500000,'pending':False,'deleting':False}
    auto=auto_record();auto['port']=40003
    auto['runtime']['dirs']['up']['last_busy_at']=190.
    origin=time.time()-100
    snap={'bandwidth':{'40002':static,'40003':auto},'boot_origin':origin}
    q.install_bandwidth(snap)
    result=q.bandwidth(nodes,q.nft_rows())
    assert result['40002']['up'] == 1250000 and result['40002']['down'] == 2500000
    restored=result['40003']
    assert restored['up'] == auto['up'] and restored['down'] == auto['down']
    wall_deadline=time.time()-q.boottime()+restored['runtime']['dirs']['up']['until']
    assert abs(wall_deadline-(origin+310)) < 1
    assert restored['tc_prefs'] != auto['tc_prefs']
    # Reapplying a never-opened stage must retain owned local tc slots.
    prefs=copy.deepcopy(restored['tc_prefs'])
    q.install_bandwidth(snap)
    assert q.bandwidth(nodes,q.nft_rows())['40003']['tc_prefs'] == prefs
    try:
        q.bandwidth(nodes,q.nft_rows(),target=True)
        raise AssertionError('existing target policies accepted')
    except q.Error:
        pass

assert mod.port_file(443).read_bytes() == main_bytes
assert mod.nft_ok(443,main) and mod.tc_ok(443,main,'eth0')
assert root_before == [(r['kind'],r['handle']) for r in mod.tc_qdiscs('eth0') if r.get('root')]
print(json.dumps({'passed':['pristine target portbw inspection','static up/down nft+tc restore',
                           'auto hold/cooldown clock rebase','last confirmed busy deadline',
                           'retry preserves owned tc slots','port 443 policy and root qdisc retained']},indent=2))
