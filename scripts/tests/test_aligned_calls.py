import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import soak_aligned_calls as a

class Aligned(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.bin=Path(cls.tmp.name)/'control'
        source=Path(a.__file__).parent/'alignedcontrol/main.c'
        subprocess.run(['gcc','-Wall','-Wextra','-Werror','-g','-O1','-fno-optimize-sibling-calls','-fno-omit-frame-pointer','-no-pie','-pthread','-o',str(cls.bin),str(source)],check=True)
        cls.plan=a.context.plan(cls.bin,a.symbols(False));cls.site=a.direct.call_site(cls.plan)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def rows(self):
        p=self.plan;site=self.site;rows=[]
        def add(event,**kw):
            n=len(rows)+1;row=dict(event=event,pid=42,tid=42,uid=1001,seq=n,ns=n*10,site=0,sp=0,size=0,value=0,tag=0,flags=0);row.update(kw);rows.append(row)
        add('exec',path=p['binary'])
        add('call',site=site['call'],sp=9000,size=131072,tag=1)
        add('mmap_entry',size=131072,tag=34,flags=3)
        add('mmap_exit',value=0x800000)
        add('after',site=site['after'],sp=9000,value=0x800000)
        add('context_entry',kind=5,site=p['functions']['5']['address'],sp=9000,a0=1,a1=2,a2=3,a3=7)
        add('context_entry',kind=4,site=p['functions']['4']['address'],sp=8900,a0=1048576,a1=1048576,a2=123,a3=0)
        add('mmap_entry',size=2097152,tag=34,flags=3)
        add('mmap_exit',value=0x1001000)
        add('sys_enter',call='munmap',a0=0x1001000,a1=0xff000)
        add('sys_exit',call='munmap',value=0)
        add('sys_enter',call='munmap',a0=0x1200000,a1=0x1000)
        add('sys_exit',call='munmap',value=0)
        add('context_ret',kind=4,site=p['functions']['4']['address']+p['functions']['4']['ret_offsets'][0],sp=8900,a0=0,a1=0,a2=0,a3=0,value=0x1100000)
        add('context_ret',kind=5,site=p['functions']['5']['address']+p['functions']['5']['ret_offsets'][0],sp=9000,a0=0,a1=0,a2=0,a3=0,value=0x1100000)
        return rows
    def parse(self,rows):
        raw='\n'.join(json.dumps(r) for r in [dict(event='begin',pid=42)]+rows+[dict(event='end',pid=42)])+f'\n@seq[42]: {len(rows)}'
        return a.audit(raw,self.plan,1001)
    def test_native_control_runs(self):
        rows=[json.loads(s) for s in subprocess.check_output([str(self.bin)],text=True).splitlines()]
        self.assertEqual(len(rows),32);self.assertEqual(len({r['tid'] for r in rows}),4)
        self.assertTrue(all(r['pointer']%r['alignment']==0 for r in rows))
    def test_real_instruction_guard(self):
        self.assertEqual(set(a.qualify(self.plan)),{'4','5'})
        program=a.program(self.plan);self.assertNotIn('uretprobe',program);self.assertIn('nsecs(monotonic)',program)
    def test_layout_mutation_rejected(self):
        p=copy.deepcopy(self.plan);p['functions']['4']['ret_offsets']=[1]
        with self.assertRaises(ValueError):a.qualify(p)
    def test_full_parse_restores_original_ids(self):
        result=self.parse(self.rows());c=result['aligned_calls'][0]
        self.assertEqual(c['mmap_id'],'42:8');self.assertEqual(c['surviving_at_return_bytes'],1048576)
        self.assertEqual(result['aligned_with_ap32_parent'],1)
        self.assertEqual(next(x for x in result['calls'] if x['id']=='42:8')['owner'],a.LABEL)
        self.assertEqual(result['events'],15)
    def test_context_event_loss_rejected(self):
        rows=self.rows();rows.pop(6)
        with self.assertRaises(ValueError):self.parse(rows)
    def test_sp_mismatch_rejected(self):
        rows=self.rows();rows[-2]['sp']+=8
        with self.assertRaises(ValueError):self.parse(rows)
    def test_return_alignment_rejected(self):
        rows=self.rows();rows[-2]['value']+=4096
        with self.assertRaises(ValueError):self.parse(rows)
    def test_failed_trim_rejected(self):
        rows=self.rows();rows[10]['value']=(1<<64)-22
        with self.assertRaises(ValueError):self.parse(rows)
    def test_wrong_trim_range_rejected(self):
        rows=self.rows();rows[9]['a1']-=4096
        with self.assertRaises(ValueError):self.parse(rows)
    def test_wrong_mapping_flags_rejected(self):
        rows=self.rows();rows[7]['tag']=50
        with self.assertRaises(ValueError):self.parse(rows)
    def test_syscall_crossing_context_rejected(self):
        rows=self.rows();rows[7]['ns']=rows[6]['ns']
        with self.assertRaises(ValueError):self.parse(rows)
    def test_postexec_uid_rejected(self):
        rows=self.rows();rows[6]['uid']=0
        with self.assertRaises(ValueError):self.parse(rows)
    def test_unplanned_site_rejected(self):
        rows=self.rows();rows[6]['site']+=1
        with self.assertRaises(ValueError):self.parse(rows)
    def test_context_only_thread_preserved(self):
        rows=self.rows();raw,back=a.project(rows,{42:15},[dict(event='begin',pid=42),dict(event='end',pid=42)])
        self.assertNotIn('context_entry',raw);self.assertEqual(back[(42,6)],8)
    def test_clock_reverse_rejected(self):
        rows=self.rows();rows[7]['ns']=rows[6]['ns']-1
        with self.assertRaises(ValueError):self.parse(rows)
    def test_missing_ap32_rejected(self):
        rows=[r for r in self.rows() if r.get('kind')!=5]
        for n,r in enumerate(rows,1):r['seq']=n
        with self.assertRaises(ValueError):self.parse(rows)
    def test_ambiguous_mapping_rejected(self):
        parsed=self.parse(self.rows());f=next(f for f in parsed['context_frames'] if f['kind']==4)
        calls=copy.deepcopy(parsed['calls']);next(c for c in calls if c['id']=='42:8')['ambiguous']=True
        with self.assertRaisesRegex(ValueError,'ambiguity'):a.validate_aligned(f,calls)
if __name__=='__main__':unittest.main()
