import gzip,json,struct,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import soak_pagemap as p

class PagemapTests(unittest.TestCase):
    def test_pfn_and_swap_offsets_never_serialized(self):
        entries=[(1<<63)|(1<<56)|123456789,(1<<62)|7654321,0]
        raw=p.encode_flags(struct.pack('<QQQ',*entries))
        self.assertEqual(list(struct.unpack('<HHH',raw)),[258,128,0])
    def test_short_read_rejected(self):
        with patch.object(p.os,'pread',return_value=b'bad'):
            with self.assertRaisesRegex(ValueError,'incomplete'):p.read_flags(1,4096,1)
        with self.assertRaises(ValueError):p.encode_flags(b'bad')
    def test_invalid_status_and_length_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            f=Path(t)/'flags.gz';f.write_bytes(gzip.compress(struct.pack('<H',384)))
            with self.assertRaisesRegex(ValueError,'invalid'):p.flags(f,1)
            with self.assertRaisesRegex(ValueError,'length'):p.flags(f,2)
    def test_zero_and_present_counts_are_separate_states(self):
        self.assertEqual(p.stats([256,128,0])['present_pages'],1)
        self.assertEqual(p.stats([256,128,0])['swapped_pages'],1)
        self.assertEqual(p.stats([256,128,0])['neither_pages'],1)
    def test_generation_change_cannot_inherit_page_origin(self):
        a=[(4096,8192,p.life.LABEL,'old')];b=[(4096,8192,p.life.LABEL,'new')]
        self.assertEqual(p.page_origin(4096,a,a,[4096],[4096],[],[],True),(p.life.LABEL,'old'))
        self.assertEqual(p.page_origin(4096,a,b,[4096],[4096],[],[],True),('unresolved',None))
    def test_mutation_or_topology_change_invalidates_origin(self):
        s=[(4096,8192,p.life.LABEL,'old')]
        self.assertEqual(p.page_origin(4096,s,s,[4096],[4096],[(8191,8192)],[8191],True),('unresolved',None))
        self.assertEqual(p.page_origin(4096,s,s,[4096],[4096],[],[],False),('unresolved',None))
    def test_partial_page_not_falsely_covered(self):
        s=[(4096,8191,p.life.LABEL,'old')]
        self.assertEqual(p.at_page(4096,s,[4096]),('unresolved',None))
    def test_interval_union(self):
        self.assertEqual(p.union([(4096,8192),(1,2),(2,3),(8191,9000)]),[(1,3),(4096,9000)])
    def test_retention_ack_hook_default_and_injection(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);binary=root/'binary';binary.touch()
            normal=p.retention.Collector(root,binary)
            self.assertIs(normal.acknowledger,p.retention.acknowledge)
            hook=lambda *_:None;injected=p.retention.Collector(root,binary,acknowledger=hook)
            self.assertIs(injected.acknowledger,hook)
    def test_page_ack_waits_for_capture_and_is_released_once(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/'native').mkdir();(root/'native/report.json').write_text('{}');released=[]
            record=dict(key=['poststop_gc',120],file='retention/last.gz',point=dict(phase='poststop_gc',at_seconds=120))
            class Fake:
                def __init__(self,*args,acknowledger):
                    self.hook=acknowledger;self.active=SimpleNamespace(pid=10,verified=True,start='start',records=[]);self.records=[record]
                def __call__(self):self.hook(root,{},self.records)
            def captured(*args):
                (root/'captured.bin').write_bytes(b'status');return dict(key=record['key'],page_finished_ns=time.monotonic_ns())
            def ack(*args):
                self.assertTrue((root/'captured.bin').exists());self.assertTrue((root/'page-observer-ack.json').exists())
                self.assertEqual(len(json.loads((root/'page-status-index.json').read_text())['records']),1);released.append(True)
            with patch.object(p.retention,'Collector',Fake),patch.object(p,'capture',side_effect=captured),patch.object(p.retention,'acknowledge',side_effect=ack):
                collector=p.Collector(root,root/'binary',retained=True);collector();collector()
            self.assertEqual(len(released),1)
    def test_capture_failure_never_releases_ack(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            class Fake:
                def __init__(self,*args,acknowledger):
                    self.active=SimpleNamespace(pid=10,verified=True,start='start',records=[])
                    self.records=[dict(key=['poststop_gc',120],file='retention/last.gz',point=dict(phase='poststop_gc',at_seconds=120))]
                def __call__(self):pass
            with patch.object(p.retention,'Collector',Fake),patch.object(p,'capture',side_effect=ValueError('capture failed')),patch.object(p.retention,'acknowledge') as ack:
                collector=p.Collector(root,root/'binary',retained=True)
                with self.assertRaisesRegex(ValueError,'capture failed'):collector()
                ack.assert_not_called();self.assertFalse((root/'page-observer-ack.json').exists())
    def test_real_disabled_control_page_observations(self):
        source=Path(__file__).resolve().parents[1]/'pagemapcontrol/main.c'
        with tempfile.TemporaryDirectory() as t:
            folder=Path(t);binary=folder/'control'
            subprocess.run(['gcc','-Wall','-Wextra','-Werror','-g','-O1','-no-pie','-fno-optimize-sibling-calls','-fno-omit-frame-pointer','-o',str(binary),str(source)],check=True)
            proc=subprocess.Popen([str(binary),str(folder),'disabled'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            records={};deadline=time.monotonic()+12
            try:
                # Some local sandboxes expose /proc from an outer PID namespace.
                # Resolve only this process's direct children and verify the ELF.
                pid=proc.pid;expected=binary.stat()
                try:actual=Path(f'/proc/{pid}/exe').stat()
                except FileNotFoundError:actual=None
                if actual is None or (actual.st_dev,actual.st_ino)!=(expected.st_dev,expected.st_ino):
                    own=Path('/proc/self/stat').read_text().split()[0]
                    matches=[]
                    for directory in Path('/proc').iterdir():
                        if not directory.name.isdigit():continue
                        try:
                            stat=(directory/'stat').read_text();parent=stat.rsplit(')',1)[1].split()[1]
                            if parent!=own:continue
                            actual=(directory/'exe').stat()
                        except (FileNotFoundError,ProcessLookupError,PermissionError):continue
                        if (actual.st_dev,actual.st_ino)==(expected.st_dev,expected.st_ino):matches.append(int(directory.name))
                    self.assertEqual(len(matches),1);pid=matches[0]
                identity=p.life.mappings.pid_identity(pid)
                while proc.poll() is None and time.monotonic()<deadline:
                    marker=folder/'marker.json'
                    if marker.exists():
                        point=json.loads(marker.read_text());phase=point['phase']
                        if phase not in records:
                            start=time.monotonic_ns();raw=Path(f'/proc/{pid}/smaps').read_text();end=time.monotonic_ns();f='maps/'+phase+'.gz';h=p.write_gzip(folder/f,raw.encode())
                            record=dict(key=phase,point=point,file=f,sha256=h,read_start_monotonic_ns=start,read_end_monotonic_ns=end)
                            captured=p.capture(folder,binary,pid,identity,record,len(records));records[phase]=(point,captured)
                    time.sleep(.005)
                out,err=proc.communicate(timeout=2)
                self.assertEqual(proc.returncode,0,err);self.assertEqual(json.loads(out)['status'],'passed');self.assertEqual(list(records),p.PHASES)
                for phase in p.PHASES[:6]:
                    point,captured=records[phase];base=point['base'];r=next(r for r in captured['ranges'] if (r['start'],r['end'])==(base,base+4*1024*1024))
                    expected=0 if phase in ('untouched','discarded','failed_advice') else 1024
                    for f in ('first_file','second_file'):
                        values=p.flags(folder/r[f],1024);self.assertEqual(p.stats(values)['present_pages'],expected);self.assertTrue(all(v<=511 for v in values))
                    self.assertEqual(point['thp_disabled'],1)
                    source_raw=gzip.open(folder/captured['source_file'],'rt').read()
                    self.assertEqual(p.huge(source_raw,base,base+4*1024*1024),0)
                    central=next(v for v in p.selected(source_raw) if (v['start'],v['end'])==(base,base+4*1024*1024))
                    self.assertEqual(central['bytes']['Rss'],0 if phase in ('untouched','read_zero','discarded','failed_advice') else 4*1024*1024)
            finally:
                if proc.poll() is None:proc.kill();proc.wait()

if __name__=='__main__':unittest.main()
