"""Expiry and lock boundaries: real files/flock, simulated systemd/kernel only."""
import copy
import fcntl
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_qianyi import q, node, kernel, ip_kernel, SID, GIB


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.real_verify_protection=q.verify_protection
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.now=1500000000
        self.lock_paths=[str(self.root/'locks'/str(i)) for i in range(len(q.LOCKS))]
        self.states={}; self.listeners=set(); self.calls=[]
        self.mock('STATE',self.root/'state')
        self.mock('UNIT',str(self.root/'units'))
        self.mock('LOCKS',self.lock_paths)
        self.mock('node_paths',side_effect=self.paths)
        self.mock('boot_id',return_value='new-boot')
        clock=patch.object(q.time,'time',side_effect=lambda:self.now)
        clock.start();self.addCleanup(clock.stop)
        self.mock('active',side_effect=lambda unit:self.states.get(unit,'inactive'))
        self.mock('listening',side_effect=lambda:set(self.listeners))
        self.mock('systemctl',side_effect=self.systemctl)
        for name in ('pause_workers','hold_nodes','stop_bandwidth_worker','sync_fence',
                     'apply_restrictions','install_bandwidth','check_preserved','release_nodes',
                     'resume_workers','refresh_subscription','check_wg'):
            self.mock(name)
        self.restore=self.mock('restore_quota_ip')
        self.verify=self.mock('verify_protection',side_effect=lambda ns:self.assert_locked())

    def mock(self,name,*args,**kwargs):
        p=patch.object(q,name,*args,**kwargs);result=p.start();self.addCleanup(p.stop)
        return result

    def paths(self,tag,port):
        return {key:str(self.root/'nodes'/tag/key) for key in ('meta','config','url','unit','quota','iplimit')}

    def write_node(self,n):
        for key,path in self.paths(n['meta']['TAG'],n['meta']['PORT']).items():
            if n.get(key) is not None:
                q.atomic(path,q.env_bytes(n[key]) if isinstance(n[key],dict) else n[key].encode())

    def expired(self,port=40001):
        n=node(port);n['meta']['EXPIRE_EPOCH']=str(self.now)
        n['meta']['DURATION_SECONDS']=str(self.now-int(n['meta']['CREATE_EPOCH']))
        for key in ('EXPIRE_EPOCH','DURATION_SECONDS'):n['quota'][key]=n['meta'][key]
        n['unit']=q.canonical_unit(n['meta']);q.validate_node(n)
        return n

    def init(self,nodes,role='target',phase='READY',bandwidth=None):
        snap={'nodes':nodes,'bandwidth':bandwidth or {},'boot_origin':0}
        q.update_session(SID,sid=SID,role=role,phase=phase,ready_boot='old-boot',
                         nodes=nodes,protected={},snapshot_sha='hash')
        q.save(q.session_path(SID)/'snapshot.json',snap)
        return snap

    def assert_locked(self,held=True):
        for path in self.lock_paths:
            fd=os.open(path,os.O_RDWR)
            try:
                if held:
                    with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                else:
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(fd)

    def systemctl(self,action,*args,**kwargs):
        self.calls.append((action,args))
        if action == 'stop':
            for unit in args:
                self.states[unit]='inactive'
                self.listeners.discard(int(unit.split('test')[1].split('.')[0]))
        elif action == 'start':
            self.assert_locked(False)  # gate/boot must be able to acquire them
            for unit in args:
                self.states[unit]='active'
                self.listeners.add(int(unit.split('test')[1].split('.')[0]))

    def test_ready_skips_removed_expired_node_and_its_bandwidth(self):
        live=node();expired=self.expired();self.write_node(live)
        current=copy.deepcopy(live)
        current['quota']=q.settled_quota(live['quota'],10*GIB,self.now)
        self.write_node(current)
        snap=self.init([live,expired],bandwidth={'40000':{'kept':True},'40001':{'expired':True}})
        q.recover_ready(SID,snap)
        restored=self.restore.call_args.args[0]
        self.assertEqual(len(restored),1)
        self.assertEqual(restored[0]['quota']['SAVED_USED_BYTES'],str(70*GIB))
        self.assertEqual(q.install_bandwidth.call_args.args[0]['bandwidth'],{'40000':{'kept':True}})
        self.assertEqual(q.session(SID)['ready_boot'],'new-boot')
        self.assertFalse(Path(self.paths(expired['meta']['TAG'],'40001')['meta']).parent.exists())

    def test_ready_all_expired_never_recreates_files_or_bandwidth(self):
        n=self.expired();snap=self.init([n],bandwidth={'40001':{'expired':True}})
        q.recover_ready(SID,snap)
        self.assertEqual(self.restore.call_args.args[0],[])
        self.assertEqual(q.hold_nodes.call_args.args[1],[])
        self.assertEqual(q.install_bandwidth.call_args.args[0]['bandwidth'],{})
        self.assertFalse((self.root/'nodes').exists())

    def test_ready_live_missing_file_fails_without_restore(self):
        for missing in ('meta','config','url','unit','quota','iplimit'):
            with self.subTest(missing=missing):
                n=node();self.write_node(n);snap=self.init([n])
                Path(self.paths(n['meta']['TAG'],'40000')[missing]).unlink()
                self.restore.reset_mock()
                with self.assertRaises(q.Error):q.recover_ready(SID,snap)
                self.restore.assert_not_called()
                self.assertEqual(q.session(SID)['ready_boot'],'old-boot')

    def test_ready_failed_stop_cannot_be_hidden_by_missing_unit(self):
        n=self.expired();snap=self.init([n])
        self.states[n['meta']['TAG']+'.service']='active'
        with patch.object(q,'systemctl',return_value='stop failed'):
            with self.assertRaises(q.Error):q.recover_ready(SID,snap)
        self.restore.assert_not_called()

    def test_ready_rejects_changed_expiry(self):
        n=node();snap=self.init([n]);changed=copy.deepcopy(n)
        for record in (changed['meta'],changed['quota']):
            record['EXPIRE_EPOCH']=str(int(record['EXPIRE_EPOCH'])+1)
            record['DURATION_SECONDS']=str(int(record['DURATION_SECONDS'])+1)
        self.write_node(changed)
        with self.assertRaises(q.Error):q.recover_ready(SID,snap)
        self.restore.assert_not_called()

    def test_ready_retry_keeps_reset_applied_before_interruption(self):
        n=node();self.now=1900000001;self.write_node(n);snap=self.init([n])
        quota_path=self.paths(n['meta']['TAG'],'40000')['quota']
        def interrupted(ns,**kwargs):
            q.atomic(quota_path,q.env_bytes(q.apply_due(ns[0]['quota'],self.now)))
            raise q.Error('interrupted after persistent reset')
        self.restore.side_effect=interrupted
        with self.assertRaises(q.Error):q.recover_ready(SID,snap)
        reset=Path(quota_path).read_bytes();self.now+=10
        self.restore.side_effect=None
        q.recover_ready(SID,snap)
        restored=self.restore.call_args.args[0][0]['quota']
        self.assertEqual(restored,q.metadata(reset))
        self.assertEqual(restored['LAST_RESET_EPOCH'],'1900000001')
        self.assertEqual(restored['NEXT_RESET_EPOCH'],str(1900000000+2592000))

    def test_resumed_uses_live_balance_and_does_not_replay_policies(self):
        n=node();expired=self.expired();self.init([n,expired],role='source',phase='RESUMED')
        current=copy.deepcopy(n);current['quota']=q.settled_quota(n['quota'],10*GIB,self.now)
        self.write_node(current)
        quota_path=self.paths(n['meta']['TAG'],'40000')['quota']
        before=Path(quota_path).read_bytes()
        rows=kernel(current['quota'],3*GIB)+ip_kernel()
        self.mock('nft_rows',return_value=rows)
        self.mock('bandwidth',return_value={})
        self.mock('library',return_value='active')
        original_verify=self.verify
        def inspect(ns):
            self.assert_locked()
            self.assertEqual(len(ns),1)
            self.assertEqual(ns[0]['quota']['SAVED_USED_BYTES'],str(70*GIB))
            self.assertEqual(q.quota_live(ns[0]['quota'],q.nft_rows()),3*GIB)
            self.assertEqual(Path(quota_path).read_bytes(),before)
            self.real_verify_protection(ns)
        original_verify.side_effect=inspect
        q.finish_source_resume(SID)
        self.assertEqual(original_verify.call_count,2)
        self.restore.assert_not_called();q.apply_restrictions.assert_not_called();q.install_bandwidth.assert_not_called()
        self.assertEqual(Path(quota_path).read_bytes(),before)
        self.assertEqual(q.quota_live(current['quota'],rows),3*GIB)
        self.assertNotIn(('start',(expired['meta']['TAG']+'.service',)),self.calls)

    def test_resumed_all_expired_finishes_without_files_or_starts(self):
        self.init([self.expired()],role='source',phase='RESUMED')
        q.finish_source_resume(SID)
        self.assertEqual(self.verify.call_args.args[0],[])
        self.assertFalse(self.calls)
        self.restore.assert_not_called();q.resume_workers.assert_called_once()

    def test_expired_listener_prevents_resume_and_target_verification(self):
        n=self.expired();self.listeners={40001}
        for role,phase,operation in [('source','RESUMED',q.finish_source_resume),('target','READY',q.verify_target)]:
            with self.subTest(role=role):
                self.init([n],role=role,phase=phase)
                with self.assertRaises(q.Error):operation(SID)
                self.restore.assert_not_called();q.sync_fence.assert_not_called()

    def test_resumed_unexpired_missing_quota_keeps_fence_and_workers(self):
        n=node();self.init([n],role='source',phase='RESUMED');self.write_node(n)
        Path(self.paths(n['meta']['TAG'],'40000')['quota']).unlink()
        with self.assertRaises(q.Error):q.finish_source_resume(SID)
        q.sync_fence.assert_not_called();q.resume_workers.assert_not_called();self.restore.assert_not_called()

    def test_resumed_missing_live_counters_never_rebuilds_them(self):
        n=node();self.init([n],role='source',phase='RESUMED');self.write_node(n)
        def inspect(ns):
            self.assert_locked()
            q.quota_live(ns[0]['quota'],[])
        self.verify.side_effect=inspect
        with self.assertRaises(q.Error):q.finish_source_resume(SID)
        self.restore.assert_not_called();q.release_nodes.assert_not_called();q.sync_fence.assert_not_called()

    def test_resumed_reads_current_files_only_while_locked(self):
        n=node();self.init([n],role='source',phase='RESUMED');self.write_node(n)
        original=q.current_nodes
        def read(ns):self.assert_locked();return original(ns)
        with patch.object(q,'current_nodes',side_effect=read) as reads:
            q.finish_source_resume(SID)
        self.assertEqual(reads.call_count,2)

    def test_resumed_rechecks_expiry_after_start(self):
        n=node();self.init([n],role='source',phase='RESUMED');self.write_node(n)
        def start(action,*args,**kwargs):
            self.assert_locked(False)
            self.now=int(n['meta']['EXPIRE_EPOCH'])
            for path in self.paths(n['meta']['TAG'],'40000').values():Path(path).unlink()
        with patch.object(q,'systemctl',side_effect=start):q.finish_source_resume(SID)
        self.assertEqual(self.verify.call_args.args[0],[])
        self.restore.assert_not_called()

    def test_verify_reads_metadata_under_locks_and_reports_removed_expired(self):
        n=node();self.write_node(n);self.init([n,self.expired()])
        self.states[n['meta']['TAG']+'.service']='active';self.listeners={40000}
        self.mock('machine_id',return_value='target')
        self.mock('nft_rows',return_value=[])
        self.mock('extract_restrictions',return_value={40000:n['restrictions']})
        original=q.current_nodes
        def read(ns):self.assert_locked();return original(ns)
        with patch.object(q,'current_nodes',side_effect=read):result=q.verify_target(SID)
        self.assertEqual((result['nodes'],result['expired']),(1,1))
