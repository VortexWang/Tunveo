import json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import soak_call_lifecycle as l
class LifecycleTests(unittest.TestCase):
    def call(self,name,args,value,n=1,owner=l.LABEL,start=None,end=None):
        return dict(call=name,args=args,value=value,id=f'11:{n}',tid=11,owner=owner,start_ns=2*n if start is None else start,end_ns=2*n+1 if end is None else end,ambiguous=False)
    def mmap(self,lo=4096,size=16384,n=1,flags=34,owner=l.LABEL):return self.call('mmap',[lo,size,3,flags],lo,n,owner)
    def test_partial_unmap_survivors_keep_generation(self):
        calls=[self.mmap(),self.call('munmap',[8192,8192],0,2)]
        self.assertEqual(l.replay(calls,99),[(4096,8192,l.LABEL,'11:1'),(16384,20480,l.LABEL,'11:1')])
    def test_fixed_reuse_has_new_generation(self):
        calls=[self.mmap(),self.mmap(8192,8192,2,50,'unresolved')];s=l.replay(calls,99)
        self.assertEqual(l.cover(8192,16384,s),('unresolved',['11:2']))
        self.assertEqual(l.cover(4096,8192,s),(l.LABEL,['11:1']))
    def test_success_and_failed_advice_do_not_unmap(self):
        calls=[self.mmap(),self.call('madvise',[4096,16384,4],0,2),self.call('madvise',[4097,4096,4],(1<<64)-22,3)]
        self.assertEqual(l.replay(calls,99),l.replay(calls,3))
    def test_failed_mutator_invalidates_without_claiming_release(self):
        s=l.replay([self.mmap(),self.call('munmap',[8192,4096],(1<<64)-22,2)],99)
        self.assertEqual(l.cover(8192,12288,s),('unresolved',['11:1']))
        self.assertEqual(sum(b-a for a,b,_,_ in s),16384)
    def test_mremap_moves_and_creates_generation(self):
        calls=[self.mmap(),self.call('mremap',[4096,16384,32768,3,65536],65536,2)]
        self.assertEqual(l.replay(calls,99),[(65536,81920,l.LABEL,'11:2'),(81920,98304,'unresolved','11:2')])
        self.assertEqual(calls[1]['parent_generations'],['11:1'])
    def test_unsupported_remap_rejected(self):
        with self.assertRaisesRegex(ValueError,'unsupported'):l.replay([self.mmap(),self.call('mremap',[4096,16384,16384,5,0],65536,2)],99)
    def test_overlapping_concurrent_changes_become_unknown(self):
        a=self.mmap();a.update(start_ns=1,end_ns=5)
        b=self.call('munmap',[4096,4096],0,2,start=2,end=6)
        calls=l.prepare([a,b]);self.assertTrue(all(c['ambiguous'] for c in calls))
        self.assertEqual(l.cover(8192,20480,l.replay(calls,99))[0],'unresolved')
    def test_failed_nonfixed_mmap_does_not_remove_existing(self):
        failed=self.call('mmap',[4096,16384,3,34],(1<<64)-12,2)
        self.assertEqual(l.replay([self.mmap(),failed],99),l.replay([self.mmap()],99))
    def test_impossible_nonfixed_overlap_fails(self):
        with self.assertRaisesRegex(ValueError,'overlaps'):l.replay([self.mmap(),self.mmap(n=2)],99)
    def test_mixed_or_missing_cover_not_attributed(self):
        s=[(4096,8192,l.LABEL,'a'),(8192,12288,'unresolved','b')]
        self.assertEqual(l.cover(4096,12288,s)[0],'unresolved');self.assertEqual(l.cover(4096,16384,s),('unresolved',[]))
    def raw(self,missing=False,bad_uid=False):
        records=[dict(event='exec',site=0,path='/frozen/control',pid=10,tid=10,uid=1000,seq=1,ns=1)]
        for n,(event,site,size,value,sp) in enumerate([('call',100,4096,0,5000),('mmap_entry',0,4096,0,0),('mmap_exit',0,0,8192,0),('after',105,0,8192,5000)],1):records.append(dict(event=event,site=site,size=size,value=value,sp=sp,pid=10,tid=11,uid=1000,seq=n,ns=n+1,tag=34,flags=3))
        records.append(dict(event='sys_enter',call='madvise',a0=8192,a1=4096,a2=4,pid=10,tid=11,uid=1000,seq=5,ns=6))
        if not missing:records.append(dict(event='sys_exit',call='madvise',value=0,pid=10,tid=11,uid=1000,seq=6,ns=7))
        if bad_uid:records[-1]['uid']=0
        return '\n'.join([json.dumps(dict(event='begin',pid=10))]+[json.dumps(r) for r in records]+[json.dumps(dict(event='end',pid=10)),f'@seq[10]: 1',f'@seq[11]: {5 if missing else 6}'])
    def test_full_sequence_projection_restores_original_ids(self):
        with patch.object(l.callsite,'call_site',return_value=dict(call=100,after=105,callee_symbol='control_map')):
            r=l.parse(self.raw(),{'binary':'/frozen/control'},1000)
        self.assertEqual(len(r['calls']),2);self.assertEqual(r['calls'][0]['id'],'11:2');self.assertEqual(r['calls'][0]['validated_call_seq'],1)
        self.assertEqual(r['calls'][1]['id'],'11:5');self.assertEqual(r['call_proof']['calls'][0]['size'],4096)
    def test_missing_extra_syscall_exit_rejected(self):
        with self.assertRaisesRegex(ValueError,'unfinished'):l.parse(self.raw(missing=True),{'binary':'/frozen/control'},1000)
    def test_wrong_postexec_uid_rejected(self):
        with self.assertRaisesRegex(ValueError,'identity'):l.parse(self.raw(bad_uid=True),{'binary':'/frozen/control'},1000)
    def test_real_control_runs_and_callsite_is_exact(self):
        source=Path(__file__).resolve().parents[1]/'calllifecyclectrl/main.c'
        with tempfile.TemporaryDirectory() as t:
            binary=Path(t)/'control'
            subprocess.run(['gcc','-Wall','-Wextra','-Werror','-g','-O1','-no-pie','-fno-optimize-sibling-calls','-fno-omit-frame-pointer','-o',str(binary),str(source)],check=True)
            result=json.loads(subprocess.check_output([str(binary),t],text=True));self.assertEqual(result['status'],'passed')
            plan=l.context.plan(binary,{1:'control_site'});program=l.program(plan)
            self.assertIn('nsecs(monotonic)',program);self.assertIn('sys_enter_mremap',program);self.assertIn('sys_enter_madvise',program);self.assertNotIn('uretprobe',program)
            self.assertNotRegex(program,r'\bnsecs(?!\(monotonic\))')
if __name__=='__main__':unittest.main()
