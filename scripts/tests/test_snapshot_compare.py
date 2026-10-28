import contextlib,io,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import soak_cycles as cycles
from inventory_runtime_symbols import candidates
class StaticInventory(unittest.TestCase):
    def test_only_defined_nonzero_code_candidates(self):
        raw='00001000 00000020 T _ZN6__tsan14TracePartAllocEv\n00002000 00000000 t InternalAlloc\n00003000 00000004 D InternalAlloc\n                 U MmapOrDie\n00004000 00000010 t unrelated\n'
        rows=candidates(raw);self.assertEqual(len(rows),1);self.assertEqual(rows[0]['address'],4096);self.assertEqual(rows[0]['size'],32)
    def test_absent_symbol_is_not_invented(self):
        self.assertEqual(candidates('00004000 00000010 T runtime.main\n'),[])
class MetadataOnly(unittest.TestCase):
    def test_requires_verified_process_control_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=['cycles','--ordinary','/unused','--race','/unused','--artifacts',str(Path(tmp)/'out'),'--mapping-policy','metadata_only','--thp-control','baseline','--launcher','/unused']
            with patch.object(sys,'argv',args),patch.object(cycles.subprocess,'Popen') as launch,contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:cycles.main()
                self.assertEqual(error.exception.code,2);launch.assert_not_called();self.assertFalse((Path(tmp)/'out').exists())
