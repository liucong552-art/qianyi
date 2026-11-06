"""Synthetic users only. Does not require root, network, nftables or systemd."""
import base64
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import itertools
import unittest
from unittest.mock import patch
import urllib.parse

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('qianyi',ROOT/'qianyi.py')
q=importlib.util.module_from_spec(spec); spec.loader.exec_module(q)
GIB=1024**3
SID='a'*32


def node(port=40000, nat=False, key=1):
    """Deterministic test-only credentials; never a production fixture."""
    private=base64.urlsafe_b64encode(bytes([key])*32).decode().rstrip('=')
    tag=f'vless-temp-test{port}'
    m={'TAG':tag,'ID':f'test{port}','PORT':str(port),'PUBLIC_DOMAIN':f'user{port}.example.com',
       'IP_VERSION':'4','LISTEN_ADDR':'0.0.0.0','UUID':f'00000000-0000-4000-8000-{port:012d}',
       'CREATE_EPOCH':'1000000000','EXPIRE_EPOCH':'2000000000','DURATION_SECONDS':'1000000000',
       'REALITY_DEST':'www.example.com:443','REALITY_SNI':'www.example.com',
       'SHORT_ID':'0123456789abcdef','PBK':q.public_key(private),'PQ_GIB':'100',
       'PQ_LIMIT_BYTES':str(100*GIB),'IP_LIMIT':'2','IP_STICKY_SECONDS':'120'}
    inbound={'listen':'0.0.0.0','port':port,'protocol':'vless',
             'settings':{'clients':[{'id':m['UUID'],'flow':'xtls-rprx-vision'}],'decryption':'none'},
             'streamSettings':{'network':'tcp','security':'reality','realitySettings':{
                 'show':False,'dest':m['REALITY_DEST'],'xver':0,'serverNames':[m['REALITY_SNI']],
                 'privateKey':private,'shortIds':[m['SHORT_ID']]}}}
    config={'log':{'loglevel':'warning'},'inbounds':[inbound],
            'outbounds':[{'tag':'direct','protocol':'freedom'},{'tag':'block','protocol':'blackhole'}]}
    if nat:
        m.update(LANDING='nat',WG_IF='wg-nat',MARK='2333',TABLE_ID='100',RULE_PRIORITY='31000',HANDSHAKE_MAX='180',SERVER_ADDR=m['PUBLIC_DOMAIN'])
        inbound['tag']=tag
        config['outbounds'][0]={'tag':'nat','protocol':'freedom','settings':{'domainStrategy':'UseIPv4'},
                                'streamSettings':{'sockopt':{'mark':2333}}}
        config['routing']={'rules':[{'type':'field','inboundTag':[tag],'outboundTag':'nat'}]}
    quota={'PORT':str(port),'ORIGINAL_LIMIT_BYTES':str(100*GIB),'SAVED_USED_BYTES':str(60*GIB),
           'LIMIT_BYTES':str(40*GIB),'OWNER_KIND':'temp','OWNER_TAG':tag,'DURATION_SECONDS':m['DURATION_SECONDS'],
           'EXPIRE_EPOCH':m['EXPIRE_EPOCH'],'RESET_INTERVAL_SECONDS':'2592000','NEXT_RESET_EPOCH':'1900000000',
           'CREATED_EPOCH':m['CREATE_EPOCH'],'LAST_RESET_EPOCH':'0','LAST_SAVE_EPOCH':'1000000001','REBUILD_PENDING':'0'}
    il={'PORT':str(port),'OWNER_KIND':'temp','OWNER_TAG':tag,'IP_LIMIT':'2','IP_STICKY_SECONDS':'120',
        'IP_VERSION':'4','SET_NAME':'vr_il4_'+str(port),'CREATED_EPOCH':m['CREATE_EPOCH']}
    params={'type':'tcp','security':'reality','encryption':'none','flow':'xtls-rprx-vision',
            'sni':m['REALITY_SNI'],'fp':'chrome','pbk':m['PBK'],'sid':m['SHORT_ID']}
    url=f'vless://{m["UUID"]}@{m["PUBLIC_DOMAIN"]}:{port}?'+urllib.parse.urlencode(params)+'#'+tag+'\n'
    return {'meta':m,'config':json.dumps(config),'unit':q.canonical_unit(m),'url':url,
            'quota':quota,'iplimit':il,'disabled':False,'restrictions':{'paused':False,'bans':[]}}


def kernel(quota, live=0, in_bytes=0, out_bytes=0):
    p=quota['PORT']; rows=[]
    if int(quota['LIMIT_BYTES']):
        rows.append({'quota':{'family':'inet','table':'vr_pq','name':'vr_pq_q_'+p,
                              'bytes':int(quota['LIMIT_BYTES']),'used':live,'inv':True}})
        for direction,used in [('in',in_bytes),('out',out_bytes)]:
            rows.append({'counter':{'table':'vr_pq','name':'vr_pq_'+direction+'_'+p,'bytes':used}})
    for direction in ('in','out'):
        match={'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport' if direction=='in' else 'sport'}},'right':int(p)}}
        expr=[match,{'quota':'vr_pq_q_'+p},{'drop':None}] if int(quota['LIMIT_BYTES']) else [match,{'drop':None}]
        rows.append({'rule':{'table':'vr_pq','chain':'pq_input' if direction=='in' else 'pq_output',
                            'comment':'vr-pq-drop-'+direction+'-'+p,'expr':expr}})
        if int(quota['LIMIT_BYTES']):
            rows.append({'rule':{'table':'vr_pq','chain':'pq_input' if direction=='in' else 'pq_output',
                                'comment':'vr-pq-count-'+direction+'-'+p,'expr':[match,{'counter':'vr_pq_'+direction+'_'+p}]}})
    return rows


def auto_record():
    def direction(phase,until):
        return {'phase':phase,'until':until,'last':None,'high_since':None,'progress':0.,
                'monitor_start_bytes':None,'mbps':None,'lower_mbps':None,'reason':'test',
                'busy_since':None,'last_busy_at':None}
    return {'port':40000,'up':2250000,'down':5000000,'pending':False,'deleting':False,
            'tc_prefs':{'4-tcp':40000,'4-udp':65535,'6-tcp':65534,'6-udp':65533},
            'auto':{'version':1,'base':{'up':5000000,'down':5000000},'limited':{'up':2250000,'down':2250000},
                    'trigger_bp':10000,'after':45,'hold':120,'cooldown':30},
            'runtime':{'boot_id':'b'*36,'checked_at':100.,'dirs':{
                'up':direction('hold',200.),'down':direction('cooldown',150.)}}}


def ip_kernel():
    actual=json.loads((ROOT/'tests/fixtures/nft-iplimit-debian13.json').read_text())
    rows=[{'chain':{'family':'inet','table':'vr_iplimit','name':'il_input','hook':'input','prio':-10,'type':'filter','policy':'accept'}},
          {'set':{'table':'vr_iplimit','name':'vr_il4_40000','type':'ipv4_addr','size':2,'timeout':120,'flags':['dynamic','timeout']}}]
    for part,expr in zip(actual['order'],actual['expressions']):
        rows.append({'rule':{'table':'vr_iplimit','chain':'il_input','comment':f'vr-il-{part}-40000','expr':expr}})
    return rows


class DataTests(unittest.TestCase):
    def test_nat_server_addr_is_authoritative_for_published_link(self):
        n=node(nat=True)
        n['meta']['PUBLIC_DOMAIN']='installation.example.com'
        q.validate_node(n)
        self.assertIn('user40000.example.com',n['url'])

    def test_different_keys_domains_and_node_types_survive(self):
        nodes=[node(key=1),node(40001,nat=True,key=2),node(40002,key=3)]
        wire=q.encoded(nodes)
        restored=json.loads(wire)
        for n in restored:q.validate_node(n)
        self.assertEqual(restored,nodes)
        self.assertEqual(len({n['meta']['PBK'] for n in nodes}),3)
        self.assertNotIn(b'standby.example',wire)

    def test_main_key_substitution_is_rejected(self):
        n=node(); c=json.loads(n['config'])
        c['inbounds'][0]['streamSettings']['realitySettings']['privateKey']=base64.urlsafe_b64encode(b'9'*32).decode().rstrip('=')
        n['config']=json.dumps(c)
        with self.assertRaises(q.Error):q.validate_node(n)

    def test_wrong_business_domain_rejected(self):
        n=node(); n['url']=n['url'].replace('user40000.example.com','standby.example.com')
        with self.assertRaises(q.Error):q.validate_node(n)

    def test_wrong_owner_and_pending_transaction_rejected(self):
        for key,value in [('OWNER_TAG','vless-temp-someone-else'),('REBUILD_PENDING','1')]:
            n=node(); n['quota'][key]=value
            with self.assertRaises(q.Error):q.validate_node(n)

    def test_literal_metadata_never_executes_and_duplicate_rejected(self):
        self.assertEqual(q.metadata(b'TAG=$(touch /tmp/never-run)\n')['TAG'],'$(touch /tmp/never-run)')
        with self.assertRaises(q.Error):q.metadata(b'A=1\nA=2\n')

    def test_path_traversal_and_443_rejected(self):
        for tag,port in [('vless-temp-../../etc',40000),('vless-temp-ok',443)]:
            with self.assertRaises(q.Error):q.node_paths(tag,port)

    def test_two_rotations_and_new_nodes(self):
        a=node()['quota']
        first=q.settled_quota(a,q.quota_live(a,kernel(a,live=0)),1500000000)
        second=q.settled_quota(first,q.quota_live(first,kernel(first,live=10*GIB)),1500000100)
        self.assertEqual(int(second['SAVED_USED_BYTES']),70*GIB)
        self.assertEqual(int(second['LIMIT_BYTES']),30*GIB)
        old=node(); old['quota']=second
        fresh=node(40001,key=7)
        for n in json.loads(q.encoded([old,fresh])):q.validate_node(n)
        self.assertNotEqual(old['meta']['PBK'],fresh['meta']['PBK'])

    def test_counter_max_and_limit_cap(self):
        a=node()['quota']
        self.assertEqual(q.quota_live(a,kernel(a,live=10,in_bytes=8,out_bytes=5)),13)
        s=q.settled_quota(a,99*GIB,1500000000)
        self.assertEqual(s['SAVED_USED_BYTES'],str(100*GIB));self.assertEqual(s['LIMIT_BYTES'],'0')

    def test_unreadable_counter_is_not_zero(self):
        a=node()['quota']
        for rows in ([],kernel(a)[1:], [x for x in kernel(a) if 'counter' not in x]):
            with self.assertRaises(q.Error):q.quota_live(a,rows)

    def test_exhausted_has_only_unconditional_guards(self):
        a=q.settled_quota(node()['quota'],40*GIB,1500000000)
        self.assertEqual(q.quota_live(a,kernel(a)),0)
        bad=kernel(a);bad[0]['rule']['expr'].insert(1,{'quota':'old'})
        with self.assertRaises(q.Error):q.quota_live(a,bad)

    def test_forged_quota_comment_does_not_hide_wrong_expression(self):
        a=node()['quota'];rows=kernel(a)
        rule=next(x['rule'] for x in rows if 'rule' in x)
        rule['expr'][0]['match']['right']=443
        with self.assertRaises(q.Error):q.quota_live(a,rows)

    def test_duplicate_guard_rejected(self):
        a=node()['quota'];rows=kernel(a)
        rows.append(copy.deepcopy(next(x for x in rows if 'rule' in x)))
        with self.assertRaises(q.Error):q.quota_live(a,rows)

    def test_reset_only_when_due_and_not_expired(self):
        a=node()['quota']; nxt=int(a['NEXT_RESET_EPOCH']); period=2592000
        self.assertEqual(q.apply_due(a,nxt-1),a)
        b=q.apply_due(a,nxt+period+10)
        self.assertEqual(b['SAVED_USED_BYTES'],'0')
        self.assertEqual(int(b['NEXT_RESET_EPOCH']),nxt+period*2)
        self.assertEqual(b['EXPIRE_EPOCH'],a['EXPIRE_EPOCH'])
        self.assertEqual(q.apply_due(b,nxt+period+10),b)
        self.assertEqual(q.apply_due(a,int(a['EXPIRE_EPOCH'])),a)

    def test_no_cycle_is_not_granted_a_cycle(self):
        a=node()['quota'];a.update(RESET_INTERVAL_SECONDS='0',NEXT_RESET_EPOCH='0')
        self.assertEqual(q.apply_due(a,1999999999),a)

    def test_hold_and_cooldown_rebase_across_machines(self):
        a=auto_record(); b=q.rebase_bandwidth(a,1000,1100,7,'c'*36)
        self.assertEqual(b['up'],2250000)
        self.assertEqual(b['runtime']['dirs']['up']['until'],107)
        self.assertEqual(b['runtime']['dirs']['down']['until'],57)
        self.assertNotIn('tc_prefs',b)
        self.assertEqual(a['runtime']['dirs']['up']['until'],200.)

    def test_elapsed_hold_does_not_invent_new_hold(self):
        b=q.rebase_bandwidth(auto_record(),1000,1300,7,'c'*36)
        self.assertEqual(b['runtime']['dirs']['up']['until'],7)
        self.assertEqual(b['up'],2250000)  # upstream monitor releases normally after audit

    def test_last_confirmed_busy_sample_extends_existing_hold(self):
        a=auto_record();a['runtime']['dirs']['up']['last_busy_at']=190.
        b=q.rebase_bandwidth(a,1000,1100,7,'c'*36)
        self.assertEqual(b['runtime']['dirs']['up']['until'],217.)
        self.assertIsNone(b['runtime']['dirs']['up']['last_busy_at'])
        self.assertEqual(b['up'],a['up'])

    def test_ip_timeout_and_config_are_kept_not_dynamic_occupancy(self):
        n=node();restored=json.loads(q.encoded(n))
        self.assertEqual(restored['iplimit']['IP_LIMIT'],'2')
        self.assertEqual(restored['iplimit']['IP_STICKY_SECONDS'],'120')
        self.assertNotIn('elem',restored['iplimit'])

    def test_ssh_rejects_domain_and_argument_injection(self):
        for host in ('prod.example.com','1.2.3.4;touch /tmp/bad','127.0.0.1'):
            with self.assertRaises((q.Error,ValueError)):q.ssh_args({'host':host,'port':22})
        args=q.ssh_args({'host':'8.8.8.8','port':2222,'identity':'/root/path with spaces/key'})
        self.assertIn('StrictHostKeyChecking=yes',args)
        self.assertIn('/root/path with spaces/key',args)


class DurableTests(unittest.TestCase):
    def setUp(self):
        boot=patch.object(q,'boot_id',return_value='test-current-boot');boot.start();self.addCleanup(boot.stop)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.state=Path(self.tmp.name)/'state'
        p=patch.object(q,'STATE',self.state);p.start();self.addCleanup(p.stop)

    def init(self,role='source',phase='SEALED',**kwargs):
        return q.update_session(SID,sid=SID,role=role,phase=phase,source_machine='source',target_machine='target',
                                ssh={},nodes=[node()],**kwargs)

    def test_permissions_and_atomic_snapshot(self):
        path=self.state/'secret.snapshot.json'
        q.save(path,{'key':'synthetic'})
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777,0o700)
        self.assertEqual(q.read_json(path),{'key':'synthetic'})

    def test_symlink_rejected_without_overwriting_target(self):
        actual=Path(self.tmp.name)/'original';actual.write_text('unchanged')
        linked=Path(self.tmp.name)/'linked';linked.symlink_to(actual)
        with self.assertRaises(q.Error):q.atomic(linked,b'new')
        self.assertEqual(actual.read_text(),'unchanged')

    def test_write_ahead_retry_only_owns_exact_bytes(self):
        self.init(role='target',phase='STAGING')
        path=str(Path(self.tmp.name)/'import')
        q.import_write(SID,path,b'first');q.import_write(SID,path,b'first')
        Path(path).write_bytes(b'foreign')
        with self.assertRaises(q.Error):q.import_write(SID,path,b'new')

    def test_open_records_commit_before_removing_fence(self):
        self.init(role='target',phase='READY',snapshot_sha='hash')
        q.save(q.session_path(SID)/'snapshot.json',{'nodes':[node()]})
        def fail():
            self.assertEqual(q.session(SID)['phase'],'OPEN')
            raise q.Error('simulated lost connection')
        with patch.object(q,'verify_target'),patch.object(q,'recover_ready'),patch.object(q,'start_target_nodes'),patch.object(q,'sync_fence',side_effect=fail):
            with self.assertRaises(q.Error):q.target_open(SID)
        with patch.object(q,'verify_target') as verify,patch.object(q,'sync_fence'),patch.object(q,'resume_workers'),patch.object(q,'machine_id',return_value='target'):
            self.assertEqual(q.target_open(SID)['phase'],'OPEN')
            verify.assert_not_called()

    def test_import_after_open_is_always_rejected(self):
        self.init(role='target',phase='OPEN')
        with patch.object(q,'restore_quota_ip') as restore:
            with self.assertRaises(q.Error):q.target_stage({'sid':SID})
            restore.assert_not_called()

    def test_old_snapshot_cannot_abort_live_target(self):
        self.init(role='target',phase='OPEN')
        with self.assertRaises(q.Error):q.target_abort(SID)

    def test_lost_open_response_resume_queries_only(self):
        self.init(phase='OPEN_UNCERTAIN')
        calls=[]
        def remote(settings,action,payload,**kw):
            calls.append(action)
            return {'phase':'OPEN','target_machine':'target'}
        with patch.object(q,'remote',side_effect=remote),patch.object(q,'locks',return_value=contextlib.nullcontext()),patch.object(q,'retire_source') as retire,patch.object(q,'freeze') as freeze:
            q.worker(SID)
            retire.assert_called_once_with(SID);freeze.assert_not_called()
        self.assertEqual(calls,['status','open'])

    def test_failure_before_snapshot_cannot_release_old_source(self):
        self.init(phase='FREEZING')
        with patch.object(q,'remote',return_value={'phase':'ABORTED','machine':'target'}),patch.object(q,'freeze',side_effect=q.Error('counter missing')),patch.object(q,'release_nodes') as release:
            with self.assertRaises(q.Error):q.source_abort(SID)
            release.assert_not_called()
        self.assertEqual(q.session(SID)['phase'],'FREEZING')

    def test_snapshot_binds_both_hosts_and_digest(self):
        s=self.init(role='target',phase='STAGING')
        snap={'schema':1,'sid':SID,'source_machine':'source','target_machine':'target','nodes':[node()], 'bandwidth':{}}
        with patch.object(q,'machine_id',return_value='target'):
            q.validate_snapshot(snap,s)
            s['snapshot_sha']=q.digest(q.encoded(snap))
            snap['nodes'][0]['quota']['SAVED_USED_BYTES']=str(0)
            with self.assertRaises(q.Error):q.validate_snapshot(snap,s)

    def test_ready_retry_starts_services_without_reimport(self):
        s=self.init(role='target',phase='READY',snapshot_sha='hash',ready_boot=q.boot_id())
        with patch.object(q,'validate_snapshot'),patch.object(q,'start_target_nodes') as start,patch.object(q,'verify_target'),patch.object(q,'restore_quota_ip') as restore:
            self.assertEqual(q.target_stage({'sid':SID})['phase'],'READY')
            start.assert_called_once();restore.assert_not_called()

    def test_live_usage_is_untouched_when_open_is_retried(self):
        self.init(role='target',phase='OPEN',snapshot_sha='hash')
        balance={'used':70*GIB}
        with patch.object(q,'sync_fence'),patch.object(q,'resume_workers'),patch.object(q,'machine_id',return_value='target'),patch.object(q,'restore_quota_ip',side_effect=lambda *_:balance.update(used=60*GIB)) as restore:
            q.target_open(SID)
            restore.assert_not_called()
        self.assertEqual(balance['used'],70*GIB)

    def test_public_status_does_not_expose_credentials(self):
        self.init()
        public=json.dumps(q.public_status(SID))
        self.assertNotIn('privateKey',public);self.assertNotIn('vless://',public)
        self.assertNotIn(node()['meta']['UUID'],public)

    def test_readonly_lock_does_not_create_missing_file(self):
        p=Path(self.tmp.name)/'no'/'lock'
        with q.locks([str(p)],readonly=True):pass
        self.assertFalse(p.parent.exists())

    def test_ready_recovery_is_forbidden_after_open(self):
        self.init(role='target',phase='OPEN',ready_boot='old')
        with patch.object(q,'restore_quota_ip') as restore:
            with self.assertRaises(q.Error):q.recover_ready(SID,{'nodes':[node()]})
            restore.assert_not_called()

    def test_resumed_source_retry_never_replays_balance(self):
        self.init(phase='RESUMED')
        with contextlib.ExitStack() as stack:
            for name in ['verify_protection','release_nodes','systemctl','sync_fence','resume_workers','refresh_subscription']:
                stack.enter_context(patch.object(q,name))
            stack.enter_context(patch.object(q,'locks',return_value=contextlib.nullcontext()))
            stack.enter_context(patch.object(q,'current_nodes',return_value=[node()]))
            stack.enter_context(patch.object(q,'active',return_value='active'))
            stack.enter_context(patch.object(q,'listening',return_value={40000}))
            restore=stack.enter_context(patch.object(q,'restore_quota_ip'))
            remote=stack.enter_context(patch.object(q,'remote'))
            q.worker(SID)
            restore.assert_not_called();remote.assert_not_called()

    def test_resumed_launch_finishes_without_ssh(self):
        self.init(phase='RESUMED')
        with patch.object(q,'active',return_value='inactive'),patch.object(q,'worker') as worker,patch.object(q,'ssh_args',side_effect=AssertionError('SSH not needed')),contextlib.redirect_stdout(None):
            q.launch(SID)
            worker.assert_called_once_with(SID)

    def test_gate_can_run_while_native_watchdog_holds_temp_lock(self):
        n=node();self.init(role='target',phase='OPEN')
        base=Path(self.tmp.name)/'vr'
        q.save(q.STATE/'owners.json',{n['meta']['TAG']:SID})
        for key,directory,filename in [('meta','temp',n['meta']['TAG']),('quota','quota','40000'),('iplimit','iplimit','40000')]:
            q.atomic(base/directory/(filename+'.env'),q.env_bytes(n[key]))
        paths=[str(Path(self.tmp.name)/'locks'/name) for name in ['temp','quota','iplimit','portbw']]
        for p in paths:q.atomic(p,b'')
        with q.locks(paths[:1]):
            with patch.object(q,'VR',str(base)),patch.object(q,'LOCKS',paths),patch.object(q,'check_wg'),patch.object(q,'verify_protection') as verify,patch.object(q.time,'monotonic',side_effect=itertools.count(0,100)):
                q.gate(n['meta']['TAG'])
                verify.assert_called_once()

    def test_remote_reports_safe_preflight_error_not_stderr(self):
        reply=subprocess.CompletedProcess([],0,q.encoded({'ok':False,'error':'WG MARK 不匹配'}),b'secret stderr must not leak')
        with patch.object(q,'run',return_value=reply),patch.object(q,'ssh_args',return_value=['ssh']):
            with self.assertRaises(q.Error) as error:q.remote({},'probe-target',{})
        self.assertIn('WG MARK',str(error.exception))
        self.assertNotIn('secret',str(error.exception))

    def test_failed_blacklist_boot_restore_blocks_gate_dependency(self):
        with patch.object(q,'regular',return_value=b'test persisted rules'),patch.object(q,'nft_rows',return_value=[]),patch.object(q,'systemctl',return_value='exit-code'):
            with self.assertRaises(q.Error):q.verify_ban_restore()

    def test_removed_native_bans_do_not_return_from_snapshot(self):
        self.init(role='target',phase='OPEN')
        with patch.object(q,'regular',return_value=None),patch.object(q,'nft_rows',return_value=[]),patch.object(q,'nft') as mutate:
            q.verify_ban_restore();mutate.assert_not_called()


class RestrictionTests(unittest.TestCase):
    def cidr(self,port=40000,addr='10.2.0.0',prefix=24):
        return {'rule':{'family':'inet','table':'jsh_cidrban','chain':'pre','comment':f'jshcidr:{port}:{addr}/{prefix}',
                'expr':[{'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':{'prefix':{'addr':addr,'len':prefix}}}},
                        {'match':{'op':'in','left':{'meta':{'key':'l4proto'}},'right':{'set':['udp','tcp']}}},
                        {'match':{'op':'==','left':{'payload':{'protocol':'th','field':'dport'}},'right':port}},
                        {'counter':{'packets':12,'bytes':800}},{'drop':None}]}}

    def test_cidr_ban_preserves_semantics_only_selected_ports(self):
        r=q.extract_restrictions([self.cidr(),self.cidr(443)],{40000})
        self.assertEqual(r,{40000:{'paused':False,'bans':['10.2.0.0/24']}})

    def test_forged_ban_comment_rejected(self):
        r=self.cidr();r['rule']['expr'][2]['match']['right']=443
        with self.assertRaises(q.Error):q.extract_restrictions([r],{40000})

    def test_cidr_chain_cannot_bypass_prerouting(self):
        rows=[{'table':{'name':'jsh_cidrban','family':'inet'}},{'chain':{'table':'jsh_cidrban','name':'pre','hook':'output','prio':-150,'type':'filter','policy':'accept'}},self.cidr()]
        with self.assertRaises(q.Error):q.extract_restrictions(rows,{40000})

    def test_unknown_firewall_ban_rejected(self):
        row={'rule':{'table':'custom','chain':'input','expr':[{'drop':None}]}}
        with self.assertRaises(q.Error):q.extract_restrictions([row],{40000})

    def test_pause_uses_native_port_scope(self):
        rows=[{'table':{'family':'inet','name':'pause_vless_40000'}},
              {'chain':{'table':'pause_vless_40000','name':'input','hook':'input','prio':-20,'policy':'accept'}}]
        for proto in ('tcp','udp'):
            rows.append({'rule':{'table':'pause_vless_40000','chain':'input','expr':[
                {'match':{'op':'!=','left':{'meta':{'key':'iifname'}},'right':'lo'}},
                {'match':{'op':'==','left':{'payload':{'protocol':proto,'field':'dport'}},'right':40000}},
                {'reject':{'type':'tcp reset'}} if proto == 'tcp' else {'drop':None}]}})
        self.assertTrue(q.extract_restrictions(rows,{40000})[40000]['paused'])

    def test_native_ip_timeout_and_priority(self):
        n=node();p=40000
        rows=ip_kernel()
        q.check_native_tables(rows,[n])
        rows[1]['set']['timeout']=60
        with self.assertRaises(q.Error):q.check_native_tables(rows,[n])

    def test_forged_ip_rule_cannot_bypass_exact_semantics(self):
        for kind in ('family','refresh','claim','drop'):
            rows=ip_kernel()
            rule=next(r['rule'] for r in rows if r.get('rule',{}).get('comment') == f'vr-il-{kind}-40000')
            rule['expr'][-1]={'accept':None} if kind in ('family','drop') else {'drop':None}
            with self.assertRaises(q.Error):q.check_native_tables(rows,[node()])
        rows=ip_kernel();rows[3]['rule']['expr'][2]['set']['elem']['elem']['timeout']=1
        with self.assertRaises(q.Error):q.check_native_tables(rows,[node()])

    def test_pristine_target_rejects_orphan_native_objects(self):
        with self.assertRaises(q.Error):q.check_native_tables(ip_kernel(),[],require_owned=True)

    def test_single_node_gate_allows_other_managed_ports(self):
        q.check_native_tables(ip_kernel()+kernel(node(40001)['quota']),[node()])

    def test_legacy_ipban_pair_is_converted_to_cidr(self):
        rows=[{'table':{'name':'jsh_ipban','family':'inet'}},
              {'set':{'table':'jsh_ipban','name':'banned','type':['ipv4_addr','inet_service'],
                      'elem':[{'concat':['10.1.2.3',40000]},{'concat':['10.1.2.4',443]}]}}]
        for protocol in ('tcp','udp'):
            rows.append({'rule':{'table':'jsh_ipban','chain':'pre','expr':[
                {'match':{'op':'==','left':{'concat':[{'payload':{'protocol':'ip','field':'saddr'}},
                    {'payload':{'protocol':protocol,'field':'dport'}}]},'right':'@banned'}},{'drop':None}]}})
        self.assertEqual(q.extract_restrictions(rows,{40000})[40000]['bans'],['10.1.2.3/32'])


class OrderingTests(unittest.TestCase):
    def setUp(self):
        boot=patch.object(q,'boot_id',return_value='test-current-boot');boot.start();self.addCleanup(boot.stop)

    def test_ready_after_reboot_uses_current_persistent_balance(self):
        with tempfile.TemporaryDirectory() as d,contextlib.ExitStack() as stack:
            root=Path(d);stack.enter_context(patch.object(q,'STATE',root/'state'))
            n=node();paths={k:str(root/'files'/k) for k in ('meta','config','url','unit','quota','iplimit')}
            current=copy.deepcopy(n);current['quota']=q.settled_quota(n['quota'],10*GIB,1500000000)
            for k in paths:q.atomic(paths[k],q.env_bytes(current[k]) if isinstance(current[k],dict) else current[k].encode())
            q.update_session(SID,sid=SID,role='target',phase='READY',ready_boot='previous',nodes=[n],protected={})
            stack.enter_context(patch.object(q,'node_paths',return_value=paths))
            stack.enter_context(patch.object(q,'locks',return_value=contextlib.nullcontext()))
            stack.enter_context(patch.object(q,'listening',return_value=set()))
            stack.enter_context(patch.object(q,'active',return_value='inactive'))
            order=[]
            for name in ('pause_workers','hold_nodes','stop_bandwidth_worker','sync_fence','systemctl',
                         'apply_restrictions','install_bandwidth','verify_protection','check_preserved'):
                stack.enter_context(patch.object(q,name,side_effect=lambda *a,_n=name,**kw:order.append(_n)))
            def restore(nodes,**kw):
                self.assertEqual(nodes[0]['quota']['SAVED_USED_BYTES'],str(70*GIB))
                order.append('restore')
            stack.enter_context(patch.object(q,'restore_quota_ip',side_effect=restore))
            q.recover_ready(SID,{'nodes':[n],'bandwidth':{}})
            self.assertLess(order.index('sync_fence'),order.index('restore'))
            self.assertLess(order.index('restore'),order.index('verify_protection'))
            self.assertEqual(q.session(SID)['ready_boot'],q.boot_id())

    def test_staging_reset_intent_is_stable_after_interruption(self):
        with tempfile.TemporaryDirectory() as d,contextlib.ExitStack() as stack:
            root=Path(d);stack.enter_context(patch.object(q,'STATE',root/'state'))
            n=node();snap={'schema':1,'sid':SID,'source_machine':'source','target_machine':'target','nodes':[n],'bandwidth':{}}
            paths={k:str(root/'files'/k) for k in ('meta','config','url','unit','quota','iplimit')}
            q.update_session(SID,sid=SID,role='target',phase='PREPARED',source_machine='source',target_machine='target',nodes=[n],protected={})
            stack.enter_context(patch.object(q,'node_paths',return_value=paths))
            stack.enter_context(patch.object(q,'locks',side_effect=lambda *a,**kw:contextlib.nullcontext()))
            stack.enter_context(patch.object(q,'machine_id',return_value='target'))
            stack.enter_context(patch.object(q,'nft_rows',return_value=[]))
            for name in ('check_empty','check_preserved','pause_workers','hold_nodes','stop_bandwidth_worker','sync_fence',
                         'check_wg','output','apply_restrictions','install_bandwidth','verify_protection','start_target_nodes','verify_target'):
                stack.enter_context(patch.object(q,name))
            with patch.object(q.time,'time',return_value=1900000001),patch.object(q,'restore_quota_ip',side_effect=q.Error('interruption')):
                with self.assertRaises(q.Error):q.target_stage(snap)
            first=q.regular(paths['quota'])
            with patch.object(q.time,'time',return_value=1900000005),patch.object(q,'restore_quota_ip'):
                q.target_stage(snap)
            self.assertEqual(first,q.regular(paths['quota']))
            self.assertEqual(q.metadata(first)['LAST_RESET_EPOCH'],'1900000001')

    def test_target_protection_before_start_before_open(self):
        with tempfile.TemporaryDirectory() as d,contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(q,'STATE',Path(d)/'state'))
            n=node();snap={'schema':1,'sid':SID,'source_machine':'source','target_machine':'target',
                          'nodes':[n],'bandwidth':{},'boot_origin':0}
            q.update_session(SID,sid=SID,role='target',phase='PREPARED',source_machine='source',target_machine='target',
                             nodes=[n],protected={})
            order=[]
            for name in ('check_empty','check_preserved','pause_workers','hold_nodes','stop_bandwidth_worker',
                         'sync_fence','check_wg','import_write','output','restore_quota_ip',
                         'apply_restrictions','install_bandwidth','verify_protection','start_target_nodes','verify_target'):
                stack.enter_context(patch.object(q,name,side_effect=lambda *a,_name=name,**kw:order.append(_name)))
            stack.enter_context(patch.object(q,'nft_rows',return_value=[]))
            stack.enter_context(patch.object(q,'locks',side_effect=lambda *a,**kw:contextlib.nullcontext()))
            stack.enter_context(patch.object(q,'machine_id',return_value='target'))
            q.target_stage(snap)
            self.assertLess(order.index('sync_fence'),order.index('import_write'))
            self.assertLess(order.index('restore_quota_ip'),order.index('start_target_nodes'))
            self.assertLess(order.index('apply_restrictions'),order.index('start_target_nodes'))
            self.assertLess(order.index('install_bandwidth'),order.index('start_target_nodes'))
            self.assertLess(order.index('verify_protection'),order.index('start_target_nodes'))
            self.assertEqual(q.session(SID)['phase'],'READY')

    def test_wg_mismatch_does_not_invoke_guard_or_network_mutation(self):
        m=node(nat=True)['meta']
        with patch.object(q,'regular',return_value=b'MARK=999\nTABLE_ID=100\nRULE_PRIORITY=31000\n'),patch.object(q,'run') as run:
            with self.assertRaises(q.Error):q.check_wg(m)
            run.assert_not_called()

    def frozen_fixture(self, stack, directory):
        base=Path(directory)
        stack.enter_context(patch.object(q,'STATE',base/'state'))
        stack.enter_context(patch.object(q,'VR',str(base/'vr')))
        n=node()
        paths={'meta':str(base/'vr/temp'/f'{n["meta"]["TAG"]}.env')}
        for key in ['quota','iplimit','url','config','unit']:
            paths[key]=str(base/'files'/key)
        for key in ['meta','quota','iplimit']:q.atomic(paths[key],q.env_bytes(n[key]))
        for key in ['url','config','unit']:q.atomic(paths[key],n[key].encode())
        stack.enter_context(patch.object(q,'node_paths',return_value=paths))
        for name in ['pause_workers','hold_nodes','stop_bandwidth_worker','sync_fence','systemctl','check_preserved','check_native_tables']:
            stack.enter_context(patch.object(q,name))
        stack.enter_context(patch.object(q,'active',return_value='inactive'))
        stack.enter_context(patch.object(q,'listening',return_value=set()))
        stack.enter_context(patch.object(q,'locks',side_effect=lambda *a,**kw:contextlib.nullcontext()))
        stack.enter_context(patch.object(q,'boot_id',return_value='before'))
        stack.enter_context(patch.object(q,'machine_id',return_value='source'))
        stack.enter_context(patch.object(q,'bandwidth',return_value={}))
        stack.enter_context(patch.object(q,'extract_restrictions',return_value={40000:{'paused':False,'bans':[]}}))
        q.update_session(SID,sid=SID,role='source',phase='FREEZING',target_machine='target',
                         info={'boot':'before'},nodes=[n],protected={})
        return n,paths

    def test_freeze_crash_replays_settlement_intent_not_old_counters(self):
        with tempfile.TemporaryDirectory() as d,contextlib.ExitStack() as stack:
            n,paths=self.frozen_fixture(stack,d)
            rows=stack.enter_context(patch.object(q,'nft_rows',return_value=kernel(n['quota'],10*GIB)))
            def crash(nodes,**kw):
                intent=q.read_json(q.session_path(SID)/'settlement.json')
                self.assertEqual(intent['nodes'][0]['quota']['SAVED_USED_BYTES'],str(70*GIB))
                raise q.Error('power loss after durable settlement')
            with patch.object(q,'restore_quota_ip',side_effect=crash):
                with self.assertRaises(q.Error):q.freeze(SID)
            rows.side_effect=AssertionError('must not read old counters again')
            with patch.object(q,'restore_quota_ip') as restore:
                snap=q.freeze(SID)
                restore.assert_called_once()
            self.assertEqual(snap['nodes'][0]['quota']['SAVED_USED_BYTES'],str(70*GIB))
            self.assertEqual(q.session(SID)['phase'],'SEALED')

    def test_counter_failure_never_writes_settlement_or_snapshot(self):
        with tempfile.TemporaryDirectory() as d,contextlib.ExitStack() as stack:
            n,paths=self.frozen_fixture(stack,d)
            stack.enter_context(patch.object(q,'nft_rows',return_value=[]))
            with patch.object(q,'restore_quota_ip') as restore:
                with self.assertRaises(q.Error):q.freeze(SID)
                restore.assert_not_called()
            self.assertFalse((q.session_path(SID)/'settlement.json').exists())
            self.assertFalse((q.session_path(SID)/'snapshot.json').exists())
            self.assertEqual(q.metadata(q.regular(paths['quota']))['SAVED_USED_BYTES'],str(60*GIB))

    def test_crash_after_snapshot_before_sealed_state_is_retryable(self):
        with tempfile.TemporaryDirectory() as d,contextlib.ExitStack() as stack:
            n,_=self.frozen_fixture(stack,d)
            stack.enter_context(patch.object(q,'nft_rows',return_value=kernel(n['quota'],10*GIB)))
            stack.enter_context(patch.object(q,'restore_quota_ip'))
            real=q.update_session
            def update(sid,**kw):
                if kw.get('phase') == 'SEALED':raise q.Error('crash at phase boundary')
                return real(sid,**kw)
            with patch.object(q,'update_session',side_effect=update):
                with self.assertRaises(q.Error):q.freeze(SID)
            self.assertTrue((q.session_path(SID)/'snapshot.json').exists())
            self.assertEqual(q.session(SID)['phase'],'FREEZING')
            q.freeze(SID)
            self.assertEqual(q.session(SID)['phase'],'SEALED')


class CliTests(unittest.TestCase):
    def test_help_and_standalone_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            dest=Path(d)/'standalone.py'
            r=subprocess.run(['python3',str(ROOT/'qianyi.py'),'build',str(dest)],capture_output=True)
            self.assertEqual(r.returncode,0,r.stderr)
            r=subprocess.run(['python3',str(dest),'--help'],capture_output=True,cwd=d)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertIn(b'preflight',r.stdout)


if __name__ == '__main__':
    unittest.main()
