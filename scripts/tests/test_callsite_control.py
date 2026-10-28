import json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import soak_callsite_control as c

class CallsiteTests(unittest.TestCase):
    site={'call':100,'after':105,'callee_symbol':'control_map'}
    def rows(self):
        rows=[]
        for event,site,size,value,sp in [('call',100,4096,0,5000),('mmap_entry',0,4096,0,0),('mmap_exit',0,0,8192,0),('after',105,0,8192,5000)]:
            n=len(rows)+1;rows.append(dict(event=event,site=site,size=size,value=value,sp=sp,pid=10,tid=11,uid=1000,seq=n,ns=n,tag=1,flags=0))
        return rows
    def run_audit(self,rows,ledger=4,prefix=None,execs=None):
        prefix=prefix or []
        if execs is None:execs=[dict(event='exec',site=0,path='/frozen/control',pid=10,tid=10,uid=1000,seq=len(prefix)+1,ns=0)]
        prefix=[dict(r,ns=r['ns']+100) for r in prefix]
        execs=[dict(r,ns=r['ns']+100) for r in execs]
        rows=[dict(r,ns=r['ns']+100) for r in rows]
        main=prefix+execs
        lines=[json.dumps(dict(event='begin',pid=10))]+[json.dumps(r) for r in main+rows]+[json.dumps(dict(event='end',pid=10)),f'@seq[11]: {ledger}']
        if main:lines.append(f'@seq[10]: {max(r["seq"] for r in main)}')
        raw='\n'.join(lines)
        with patch.object(c,'call_site',return_value=self.site):return c.audit(raw,{'binary':'/frozen/control'},1000)
    def test_completed_call_and_syscall(self):
        r=self.run_audit(self.rows());self.assertEqual(r['calls'][0]['pointer'],8192)
    def test_loss_and_duplicate_rejected(self):
        rows=self.rows()
        with self.assertRaisesRegex(ValueError,'missing/duplicate'):self.run_audit(rows[:1]+rows[2:])
        with self.assertRaisesRegex(ValueError,'missing/duplicate'):self.run_audit(rows+[rows[-1]])
    def test_incomplete_return_and_stack_mismatch(self):
        rows=self.rows()
        with self.assertRaisesRegex(ValueError,'unclosed'):self.run_audit(rows[:-1],3)
        rows[-1]['sp']+=8
        with self.assertRaisesRegex(ValueError,'stack pointer'):self.run_audit(rows)
    def test_size_and_pointer_mismatch(self):
        for field,index in [('size',1),('value',2)]:
            rows=self.rows();rows[index][field]+=4096
            with self.assertRaisesRegex(ValueError,'size/return'):self.run_audit(rows)
    def test_no_mmap_or_extra_mmap_rejected(self):
        rows=self.rows();rows=[rows[0],rows[-1]]
        for n,r in enumerate(rows,1):r['seq']=n;r['ns']=n
        with self.assertRaisesRegex(ValueError,'exactly one mmap'):self.run_audit(rows,2)
    def test_pid_and_address_rejected(self):
        for key in ['pid','site']:
            rows=self.rows();rows[0][key]+=1
            with self.assertRaises(ValueError):self.run_audit(rows)
    def test_real_c_multithread_control_and_instruction_offsets(self):
        source=Path(__file__).resolve().parents[1]/'callsitecontrol/main.c'
        with tempfile.TemporaryDirectory() as t:
            binary=Path(t)/'control'
            subprocess.run(['gcc','-Wall','-Wextra','-Werror','-g','-O1','-fno-optimize-sibling-calls','-fno-omit-frame-pointer','-no-pie','-pthread','-o',str(binary),str(source)],check=True)
            expected=[json.loads(l) for l in subprocess.check_output([str(binary)],text=True).splitlines()]
            self.assertEqual(len(expected),32);self.assertEqual(len({r['tid'] for r in expected}),4)
            self.assertEqual(sorted(r['size'] for r in expected),[n*4096 for n in range(1,33)])
            plan=c.context.plan(binary,{1:'control_site'});site=c.call_site(plan)
            self.assertEqual(site['after'],site['call']+5)
            self.assertEqual(binary.read_bytes()[site['call_file_offset']],0xe8)
            program=c.program(plan)
            self.assertNotIn('uretprobe',program)
            self.assertIn('sys_enter_mmap',program)
            self.assertNotIn('reg("sp")',next(l for l in program.splitlines() if 'sys_enter_mmap' in l))
    def test_frozen_archive_guard(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'bad.zip';path.write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError,'digest'):c.extract(path,Path(t)/'probe')
    def test_root_launcher_mmaps_retained_before_exec(self):
        prefix=[]
        for n,event in enumerate(['mmap_entry','mmap_exit'],1):prefix.append(dict(event=event,site=0,pid=10,tid=10,uid=0,seq=n,ns=n-3,size=8192,value=8192,sp=0,tag=0,flags=0))
        r=self.run_audit(self.rows(),prefix=prefix)
        self.assertEqual(r['launcher_events'],2);self.assertEqual(r['target_exec']['uid'],1000)
        self.assertEqual(len(r['calls']),1)
    def test_missing_duplicate_or_wrong_uid_exec_rejected(self):
        with self.assertRaisesRegex(ValueError,'exec boundary'):self.run_audit(self.rows(),execs=[])
        e=dict(event='exec',site=0,path='/frozen/control',pid=10,tid=10,uid=1000,seq=1,ns=0)
        with self.assertRaisesRegex(ValueError,'exec boundary'):self.run_audit(self.rows(),execs=[e,e])
        e['uid']=0
        with self.assertRaisesRegex(ValueError,'exec PID/UID'):self.run_audit(self.rows(),execs=[e])
    def test_root_event_after_exec_rejected(self):
        rows=self.rows();rows[1]['uid']=0
        with self.assertRaisesRegex(ValueError,'after target exec'):self.run_audit(rows)
    def test_reexec_after_target_rejected(self):
        rows=self.rows();rows.append(dict(event='exec',path='/unexpected',site=0,pid=10,tid=11,uid=1000,seq=5,ns=5))
        with self.assertRaisesRegex(ValueError,'unexpected exec'):self.run_audit(rows,5)

if __name__=='__main__':unittest.main()
