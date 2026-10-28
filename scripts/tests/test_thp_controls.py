import json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from soak_cycles import control_environment,thp_observation
class THPGuards(unittest.TestCase):
    def test_environment_isolated(self):
        e={'PATH':'x'};self.assertEqual(control_environment('go_heap',e)['GODEBUG'],'disablethp=1');self.assertNotIn('GODEBUG',e)
        self.assertNotIn('GODEBUG',control_environment('baseline',e))
        with self.assertRaises(ValueError):control_environment('process',{'GORACE':'x'})
    def test_target_readback_required(self):
        with self.assertRaises(ValueError):thp_observation('',{'godebug':'','thp_enabled':'1'},'process')
    def test_go_heap_and_other_regions_differ(self):
        raw='1000-2000 rw-p 0 00:00 0 [anon: Go: heap]\nAnonHugePages: 0 kB\n2000-3000 rw-p 0 00:00 0\nAnonHugePages: 2048 kB\n'
        x=thp_observation(raw,{'godebug':'disablethp=1','thp_enabled':'1'},'go_heap');self.assertEqual(x['anon_huge_bytes'],2097152)
        with self.assertRaises(ValueError):thp_observation(raw,{'godebug':'','thp_enabled':'0'},'process')
    def test_go_heap_control_rejects_residual(self):
        with self.assertRaises(ValueError):thp_observation('1000-2000 rw-p 0 00:00 0 [anon: Go: heap]\nAnonHugePages: 2048 kB',{'godebug':'disablethp=1','thp_enabled':'1'},'go_heap')

@unittest.skipUnless(sys.platform=='linux' and shutil.which('gcc'),'Linux/gcc required')
class Launcher(unittest.TestCase):
    def test_readback_survives_exec_and_pid_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);binary=root/'launcher'
            subprocess.run(['gcc','-Wall','-Wextra','-Werror','-O1','-o',str(binary),str(Path(__file__).resolve().parents[1]/'thpcontrol/main.c')],check=True)
            code='import ctypes,json,os; print(json.dumps({"pid":os.getpid(),"state":ctypes.CDLL(None).prctl(42,0,0,0,0)}))'
            for mode,wanted in [('keep',0),('disable',1)]:
                evidence=root/(mode+'.json');out=subprocess.check_output([str(binary),mode,str(evidence),sys.executable,'-c',code],text=True);target=json.loads(out);saved=json.loads(evidence.read_text());self.assertEqual(saved,{'pid':target['pid'],'before':0,'after':wanted});self.assertEqual(target['state'],wanted)
