import json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]));import soak_mapping_ledger as l


class MappingLedgerTests(unittest.TestCase):
 def call(self,kind='mmap',start=1,end=2,args=None,value=0x1000,owner='trace_switch',id='1'):
  return dict(call=kind,start_ns=start,end_ns=end,args=args or [0,8192,3,34,0,0],value=value,owner=owner,id=id,tid=1)
 def raw_vma(self,rss=4096):
  return '1000-3000 rw-p 00000000 00:00 0\nSize: 8 kB\nRss: %d kB\nPss: %d kB\nAnonymous: %d kB\nPrivate_Dirty: %d kB\nSwap: 0 kB\n'%((rss//1024,)*4)
 def test_fixed_replacement_and_partial_unmap_preserve_generations(self):
  calls=[self.call(),self.call('munmap',3,4,[0x2000,4096],0,id='2'),self.call(start=5,end=6,args=[0x2000,4096,3,0x32,0,0],value=0x2000,owner='internal_allocator',id='3')]
  state=l.replay(l.prepare(calls),7)
  self.assertEqual(state,[(0x1000,0x2000,'trace_switch','1'),(0x2000,0x3000,'internal_allocator','3')])
  a=l.attribute(self.raw_vma(),False,l.prepare(calls),7,8)
  self.assertEqual(a['groups_rss_bytes'],{'mixed_allocators':4096})
 def test_same_owner_address_reuse_is_not_same_allocation(self):
  calls=[self.call(),self.call('munmap',4,5,[0x1000,8192],0,id='2'),self.call(start=6,end=7,id='3')]
  a=l.attribute(self.raw_vma(),False,l.prepare(calls),3,8)
  self.assertEqual(a['groups_rss_bytes'],{'unresolved':4096})
 def test_inflight_mapping_disqualifies_resident_attribution(self):
  calls=l.prepare([self.call(),self.call(start=4,end=10,id='2')])
  self.assertEqual(l.attribute(self.raw_vma(),False,calls,5,6)['groups_rss_bytes'],{'unresolved':4096})
 def test_concurrent_overlapping_mutations_are_conservative(self):
  calls=l.prepare([self.call(start=1,end=10),dict(self.call(start=2,end=8,id='2'),tid=2)])
  self.assertTrue(all(c['ambiguous'] for c in calls));self.assertEqual(l.cover(0x1000,0x3000,l.replay(calls,11))[0],'unresolved')
 def test_mremap_dontunmap_never_carries_old_known_owner(self):
  calls=l.prepare([self.call(),self.call('mremap',3,4,[0x1000,8192,8192,5,0],0x5000,id='2')])
  state=l.replay(calls,5)
  self.assertEqual(l.cover(0x1000,0x3000,state)[0],'unresolved');self.assertEqual(l.cover(0x5000,0x7000,state)[0],'unresolved')
 def test_page_rounding_and_no_rss_prorating(self):
  calls=l.prepare([self.call(args=[0,1,3,34,0,0])]);self.assertEqual(l.replay(calls,3)[0][1],0x2000)
  self.assertEqual(l.attribute(self.raw_vma(),False,calls,3,4)['groups_rss_bytes'],{'unresolved':4096})
 def test_failed_fixed_mapping_invalidates_prior_claim_conservatively(self):
  calls=l.prepare([self.call(),self.call(start=3,end=4,args=[0x1000,8192,3,0x32,0,0],value=(1<<64)-12,id='2')])
  self.assertEqual(l.cover(0x1000,0x3000,l.replay(calls,5))[0],'unresolved')
 def test_only_zero_to_final_native_timing_fields_may_change(self):
  published=dict(resources={'rss':100},counts={'tcp':2},at_seconds=2,measure_seconds=.1,checkpoint_seconds=0,snapshot_seconds=0)
  final=dict(published,checkpoint_seconds=.02,snapshot_seconds=.13)
  l.validate_published_point(published,final)
  for mutate in (lambda x:x.update(resources={'rss':101}),lambda x:x.update(counts={'tcp':3}),lambda x:x.update(at_seconds=3),lambda x:x.update(measure_seconds=.11),lambda x:x.update(checkpoint_seconds=-1),lambda x:x.update(snapshot_seconds=.01)):
   bad=dict(final);mutate(bad)
   with self.assertRaises(ValueError):l.validate_published_point(published,bad)
  with self.assertRaises(ValueError):l.validate_published_point(final,dict(final,checkpoint_seconds=.03))
 def test_brk_requests_conservatively_cover_possible_low_address_overlap(self):
  c=self.call('brk',3,4,[0x8000],0x8000,id='2')
  self.assertEqual(l.affected(c),[(0,0x8000)])
  self.assertEqual(l.affected(self.call('brk',3,4,[0],0x8000,id='3')),[])
 def plan(self):
  return {'binary':'/tmp/probe','functions':{'1':{'symbol':'parent','address':100,'ret_offsets':[10]},'3':{'symbol':'mapping','address':200,'ret_offsets':[10]}}}
 def rows(self):
  base=dict(pid=42,tid=42,uid=1001)
  data=[dict(event='exec',filename='/tmp/probe'),dict(event='entry',kind=1,site=100,sp=1000,size=0,value=0),dict(event='entry',kind=3,site=200,sp=900,size=8192,value=0),dict(event='sys_enter',call='mmap',a0=0,a1=8192,a2=3,a3=34,a4=0,a5=0),dict(event='sys_exit',call='mmap',value=0x1000),dict(event='ret',kind=3,site=210,sp=900,value=0x1000,size=0),dict(event='ret',kind=1,site=110,sp=1000,value=0,size=0)]
  return [dict(base,seq=i,ns=i,**r) for i,r in enumerate(data,1)]
 def text(self,rows):return '\n'.join([json.dumps(dict(event='begin',pid=42)),*(json.dumps(r) for r in rows),json.dumps(dict(event='end',pid=42)),'@seq[42]: '+str(len(rows))])
 def test_syscall_is_bound_to_verified_context_and_wrapper_return(self):
  a=l.parse(self.text(self.rows()),self.plan(),1001);self.assertEqual(a['calls'][0]['owner'],'trace_switch');self.assertEqual(a['calls'][0]['value'],0x1000)
 def test_sequence_context_and_wrapper_mismatches_are_rejected(self):
  for field,value in [('value',0x2000),('value',-1),('value',1<<64),('call','munmap'),('uid',0),('seq',9)]:
   rows=self.rows();rows[4][field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):l.parse(self.text(rows),self.plan(),1001)
 def test_exec_after_target_cannot_reuse_an_old_address_space(self):
  rows=self.rows()+[dict(event='exec',filename='/tmp/other',pid=42,tid=42,uid=1001,seq=8,ns=8)]
  with self.assertRaises(ValueError):l.parse(self.text(rows),self.plan(),1001)
 def test_program_uses_one_explicit_monotonic_clock_and_no_return_trampoline(self):
  p=l.program(self.plan());self.assertNotIn('uretprobe:',p);self.assertNotIn('nsecs,',p);self.assertIn('nsecs(monotonic)',p);self.assertIn('sys_enter_mremap',p);self.assertIn('sched_process_exec',p)


if __name__=='__main__':unittest.main()
