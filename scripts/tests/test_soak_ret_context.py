import copy,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).parents[1]));import soak_ret_context as c


class RetContextTests(unittest.TestCase):
 def plan(self):
  return {'binary':'/tmp/fixture','functions':{'1':{'symbol':'parent','address':100,'ret_offsets':[20]},'3':{'symbol':'mapping','address':200,'ret_offsets':[10]}}}
 def rows(self):
  rows=[]
  for seq,(event,kind,sp,site) in enumerate([('entry',1,1000,100),('entry',3,900,200),('ret',3,900,210),('ret',1,1000,120)],1):
   rows.append(dict(event=event,kind=kind,pid=42,tid=43,uid=1001,seq=seq,ns=seq,sp=sp,site=site,size=1048576 if kind==3 and event=='entry' else 0,value=4096 if event=='ret' else 0))
  return rows
 def raw(self,rows,ledger='@seq[43]: 4'):
  return '\n'.join([json.dumps(dict(event='begin',pid=42)),*(json.dumps(x) for x in rows),json.dumps(dict(event='end',pid=42)),ledger])
 def test_exact_nested_context_and_ret_value_without_unwinding(self):
  result=c.audit_events(self.raw(self.rows()),self.plan(),1001)
  self.assertEqual(result['mmap_calls'][0]['observed_contexts'],[1]);self.assertEqual(result['mmap_calls'][0]['value'],4096)
  self.assertEqual(result['matched_pairs_by_kind'],{'3':1,'1':1})
 def test_loss_duplicate_and_missing_entire_thread_rejected(self):
  for raw in (self.raw(self.rows()[:-1]),self.raw(self.rows()+[self.rows()[-1]]),self.raw(self.rows(),'@seq[43]: 4\n@seq[44]: 2'),self.raw(self.rows(),'@seq[43]: 4\n@seq[43]: 4')):
   with self.assertRaises(ValueError):c.audit_events(raw,self.plan(),1001)
 def test_sp_identity_order_and_site_are_required(self):
  for field,value in (('sp',901),('pid',99),('uid',0),('site',211),('kind',1),('ns',0)):
   rows=self.rows();rows[2][field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):c.audit_events(self.raw(rows),self.plan(),1001)
 def test_failed_mapping_not_counted_as_success(self):
  rows=self.rows();rows[2]['value']=(1<<64)-12
  self.assertFalse(c.audit_events(self.raw(rows),self.plan(),1001)['mmap_calls'][0]['successful'])
 def test_only_complete_plain_ret_instruction_ranges_supported(self):
  raw='  100:        \t55       \tpush %rbp\n  101:        \t5d       \tpop %rbp\n  102:        \tc3       \tret\n'
  self.assertEqual(c.ret_sites(raw,0x100,3),[2])
  for bad in (raw.replace('101:','103:'),raw.replace('c3','c2 04 00'),raw.replace('ret','nop')):
   with self.assertRaises(ValueError):c.ret_sites(bad,0x100,3)
 def test_generated_program_has_only_entry_and_explicit_ret_uprobes(self):
  text=c.program(self.plan());self.assertNotIn('uretprobe:',text);self.assertNotIn('ustack',text);self.assertNotIn('retval',text)
  self.assertIn('mapping+0xa',text);self.assertIn('reg("ax")',text);self.assertIn('/pid == cpid/',text)
 def test_permission_error_is_not_process_group_disappearance(self):
  with patch.object(c.subprocess,'run',return_value=SimpleNamespace(returncode=1,stderr='Operation not permitted')):
   with self.assertRaises(ValueError):c.group_alive(123)
  with patch.object(c.subprocess,'run',return_value=SimpleNamespace(returncode=1,stderr='kill: (-123): No such process')):
   self.assertFalse(c.group_alive(123))


if __name__=='__main__':unittest.main()
