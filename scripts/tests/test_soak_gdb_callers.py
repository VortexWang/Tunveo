import json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]))
import soak_gdb_callers as c


class GDBCallerTests(unittest.TestCase):
 def audit(self,records,state=None):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'mmap-calls.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in records))
   (p/'gdb-result.json').write_text(json.dumps(state or {'entry_calls':1,'returns':sum(r['event']=='return' for r in records),'exit_code':0}))
   return c.read_calls(p)
 def entry(self,bt='__sanitizer::internal_mmap'):
  return dict(event='entry',id=1,inferior_pid=50,thread_ptid=[50,51,0],registers={'rsi':1048576},backtrace=bt)
 def returned(self,address=0x100000):
  return dict(event='return',id=1,inferior_pid=50,thread_ptid=[50,51,0],rax=address)
 def test_errno_and_unreturned_calls_cannot_be_counted_as_mapped_bytes(self):
  for returned in (None,self.returned((1<<64)-1),self.returned((1<<64)-4095)):
   rows=[self.entry()]+([returned] if returned else [])
   a=self.audit(rows);self.assertFalse(a['rows'][0]['successful']);self.assertEqual(a['groups']['race_runtime_other']['cumulative_successful_virtual_bytes'],0)
 def test_return_must_belong_to_same_process_and_thread(self):
  for mutate in (lambda r:r.update(inferior_pid=99),lambda r:r.update(thread_ptid=[50,52,0])):
   r=self.returned();mutate(r)
   with self.assertRaises(ValueError):self.audit([self.entry(),r])
  with self.assertRaises(ValueError):self.audit([self.returned(),self.entry()])
  with self.assertRaises(ValueError):self.audit([self.entry(),self.returned(),self.returned()])
 def test_missing_higher_frames_are_not_guessed_as_trace(self):
  self.assertEqual(self.audit([self.entry(),self.returned()])['rows'][0]['caller_category'],'race_runtime_other')
  self.assertEqual(self.audit([self.entry('__sanitizer::internal_mmap\n__tsan::TraceSwitchPart'),self.returned()])['rows'][0]['caller_category'],'race_trace')
  self.assertEqual(self.audit([self.entry('??\nCannot access memory'),self.returned()])['rows'][0]['caller_category'],'unresolved')
 def test_nonzero_or_partial_execution_is_rejected(self):
  for state in ({'entry_calls':1,'returns':1,'exit_code':1},{'entry_calls':2,'returns':1,'exit_code':0}):
   with self.assertRaises(ValueError):self.audit([self.entry(),self.returned()],state)


if __name__=='__main__':unittest.main()
