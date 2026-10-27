import copy,gzip,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parents[1]))
import soak_page_advice as a


class PageAdviceTests(unittest.TestCase):
 def plan(self):
  return dict(binary='/probe',functions={'1':dict(symbol='parent',address=100,ret_offsets=[10]),
      '3':dict(symbol='mmap_wrapper',address=300,ret_offsets=[10])})
 def rows(self):
  data=[dict(event='exec',filename='/probe'),dict(event='entry',kind=1,site=100,sp=1000,size=0,value=0),
    dict(event='entry',kind=3,site=300,sp=900,size=8192,value=0),
    dict(event='sys_enter',call='mmap',a0=0,a1=8192,a2=3,a3=34,a4=0,a5=0),
    dict(event='sys_exit',call='mmap',value=0x1000),
    dict(event='ret',kind=3,site=310,sp=900,size=0,value=0x1000),
    dict(event='ret',kind=1,site=110,sp=1000,size=0,value=0),
    dict(event='sys_enter',call='madvise',a0=0x1000,a1=8192,a2=4),
    dict(event='sys_exit',call='madvise',value=0)]
  return [dict(pid=42,tid=42,uid=1001,seq=i,ns=i,**x) for i,x in enumerate(data,1)]
 def raw(self,rows):
  return '\n'.join([json.dumps({'event':'begin','pid':42}),*(json.dumps(x) for x in rows),
      json.dumps({'event':'end','pid':42}),'@seq[42]: '+str(len(rows))])
 def call(self,kind='mmap',start=1,end=2,args=None,value=0x1000,owner='observed_race_runtime',id='map1'):
  return dict(call=kind,tid=42,id=id,start_ns=start,end_ns=end,args=args or [0,8192,3,34,0,0],
      value=value,owner=owner,contexts=[[1,1]] if owner!='unresolved' else [])
 def advice(self,start=15,end=16,args=None,value=0):
  return self.call('madvise',start,end,args or [0x1000,4096,4],value,'unresolved','advice')
 def test_full_sequence_madvise_pairs_and_wrapper_proof(self):
  parsed=a.parse(self.raw(self.rows()),self.plan(),1001)
  self.assertEqual(parsed['events'],9);self.assertEqual(len(parsed['calls']),2)
  self.assertEqual(parsed['calls'][1]['args'],[0x1000,8192,4])
  with self.assertRaisesRegex(ValueError,'unplanned syscall'):
   a.ledger.parse(self.raw(self.rows()),self.plan(),1001)
 def test_program_uses_actual_kernel_field_names_and_monotonic_clock(self):
  text=a.program(self.plan());self.assertIn('sys_enter_madvise',text);self.assertIn('sys_exit_madvise',text)
  for field in ['start','len_in','behavior']:self.assertIn('args->'+field,text)
  self.assertIn('nsecs(monotonic)',text);self.assertNotIn('uretprobe:',text)
 def test_madvise_uid_sequence_and_pair_corruption_rejected(self):
  for index,field,value in [(7,'seq',7),(8,'call','munmap'),(8,'uid',0),(7,'a2',-1)]:
   rows=self.rows();rows[index][field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):a.parse(self.raw(rows),self.plan(),1001)
 def test_successful_discard_does_not_delete_or_reassign_mapping(self):
  calls=a.ledger.prepare([self.call(),self.advice()])
  self.assertEqual(a.ledger.replay(calls,20),a.ledger.replay(calls,10))
  event=a.describe(calls[1],calls[:1]);self.assertEqual(event['status'],'succeeded')
  self.assertEqual(event['request_origin'],'observed_race_runtime');self.assertEqual(event['generations'],['map1'])
  self.assertNotIn('reclaimed_rss',event)
 def test_failed_request_is_retained_without_claiming_no_partial_effect(self):
  event=a.describe(self.advice(value=(1<<64)-12),a.ledger.prepare([self.call()]))
  self.assertEqual((event['status'],event['errno']),('failed',12))
  self.assertIn('partial effects',event['scope'])
 def test_free_and_unknown_behavior_are_not_immediate_reclaimed_rss(self):
  for code,label in [(8,'FREE'),(12345,'OTHER'),((1<<64)-1,'OTHER')]:
   event=a.describe(self.advice(args=[0x1000,4096,code]),a.ledger.prepare([self.call()]))
   self.assertEqual(event['advice'],label);self.assertNotIn('reclaimed_rss',event)
  self.assertEqual(a.behavior((1<<64)-1),-1)
 def test_invalid_return_range_and_behavior_extension_rejected(self):
  for call in [self.advice(value=1),self.advice(args=[(1<<64)-4096,8192,4]),
               self.advice(args=[0x1000,4096,1<<40]),self.advice(args=[0x1001,4096,4])]:
   with self.assertRaises(ValueError):a.describe(call,[])
 def test_zero_length_request_has_no_mapping_claim(self):
  e=a.describe(self.advice(args=[0x1000,0,4]),[])
  self.assertEqual(e['page_range'],[0x1000,0x1000]);self.assertEqual(e['request_origin'],'empty')
 def test_address_reuse_is_bound_to_new_generation(self):
  calls=a.ledger.prepare([self.call(),self.call('munmap',3,4,[0x1000,8192],0,'unresolved','unmap'),
      self.call(start=5,end=6,owner='new_origin',id='map2')])
  e=a.describe(self.advice(),calls);self.assertEqual(e['generations'],['map2']);self.assertEqual(e['request_origin'],'new_origin')
 def test_concurrent_mapping_mutation_revokes_advice_origin(self):
  calls=a.ledger.prepare([self.call(),self.call('munmap',14,18,[0x1000,4096],0,'unresolved','unmap')])
  e=a.describe(self.advice(),calls);self.assertTrue(e['mapping_changed_during_call'])
  self.assertEqual(e['request_origin'],'unresolved')
 def snapshots(self):
  v=dict(start=0x1000,end=0x3000,path='',request_origin='observed_race_runtime',
      generations=['map1'],category='other_anonymous',rss=8192)
  old=dict(key=['measured',10],read_start_ns=10,read_end_ns=11,vmas=[v])
  new=copy.deepcopy(old);new.update(key=['poststop_gc',0],read_start_ns=20,read_end_ns=21);new['vmas'][0]['rss']=4096
  return [old,new]
 def test_neighbor_rss_is_whole_vma_not_prorated_to_request_length(self):
  parsed={'calls':[self.call(),self.advice()]}
  with patch.object(a,'snapshot_rows',return_value=self.snapshots()):out=a.audit_advice(Path('/unused'),parsed,True)
  e=out['events'][0];self.assertEqual((e['before_snapshot'],e['after_snapshot']),(0,1))
  self.assertEqual(e['requested_length'],4096)
  self.assertEqual(e['neighbor_whole_vma_deltas'][0]['rss_delta'],-4096)
  self.assertEqual(e['neighbor_whole_vma_deltas'][0]['end']-0x1000,8192)
 def test_inflight_mapping_cannot_produce_neighbor_rss_comparison(self):
  parsed={'calls':[self.call(),self.advice(),self.call('munmap',19,25,[0x1000,8192],0,'unresolved','unmap')]}
  with patch.object(a,'snapshot_rows',return_value=self.snapshots()):out=a.audit_advice(Path('/unused'),parsed,True)
  self.assertEqual(out['events'][0]['neighbor_whole_vma_deltas'],[])
 def test_coexisting_advice_is_disclosed_instead_of_single_call_causality(self):
  second=self.advice(start=17,end=18);second['id']='second'
  with patch.object(a,'snapshot_rows',return_value=self.snapshots()):
   out=a.audit_advice(Path('/unused'),{'calls':[self.call(),self.advice(),second]},True)
  self.assertEqual(out['events'][0]['neighbor_whole_vma_deltas'][0]['other_overlapping_advice'],['second'])
 def control(self):
  base=0x1000000;size=4*1024*1024
  calls=[self.call(args=[base,size,3,0x32,0,0],value=base,owner='trace_switch'),
    self.call('madvise',6,7,[base,size,4],0,'unresolved','a1'),
    self.call('madvise',11,12,[base+1,4096,4],(1<<64)-22,'unresolved','bad'),
    self.call('munmap',19,20,[base,size],0,'unresolved','unmap'),
    self.call(start=21,end=22,args=[base,size,3,0x32,0,0],value=base,owner='internal_allocator',id='map2'),
    self.call('madvise',26,27,[base,size,4],0,'unresolved','a2'),
    self.call('munmap',31,32,[base,size],0,'unresolved','final')]
  rows=[];records=[]
  for name,rss,ns in zip(['held','discarded','failed','retouched','reused','reused_discarded','released'],
                       [size,0,0,size,size,0,0],[4,9,14,17,24,29,34]):
   rows.append(dict(key=name,point={'base':base},unnamed_vmas=[] if name=='released' else
       [dict(start=base,end=base+size,rss=rss)]));records.append({'read_start_monotonic_ns':ns})
  return rows,{'records':records},a.ledger.prepare(calls)
 def test_control_requires_real_discard_retouch_reuse_and_failed_call(self):
  rows,cap,calls=self.control();a.validate_control(rows,cap,calls)
  for mutate in [lambda:rows[1]['unnamed_vmas'][0].update(rss=4*1024*1024),
                 lambda:calls[4].update(owner='trace_switch')]:
   rows,cap,calls=self.control();mutate()
   with self.assertRaises(ValueError):a.validate_control(rows,cap,calls)

 def test_resource_failure_preserves_advice_and_both_mapping_stages(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);out=root/'out';binary=root/'probe';control=root/'control'
   parsed={'native_pid':42};info={'build_info':'pinned'}
   def launch(target,folder,symbols,args,timeout,tracer,**kwargs):
    if target==binary:
     self.assertEqual(timeout,450);self.assertIn('--post-stop-observer-ack',args)
     self.assertEqual(args[args.index('--duration')+1],'180s')
     native=folder/'native';native.mkdir(parents=True)
     (native/'report.json').write_text(json.dumps({'build_info':'pinned','settings':{'pid':42}}))
    return parsed
   with patch.object(sys,'argv',['advice','--binary',str(binary),'--control',str(control),
       '--tracer','/tracer','--artifacts',str(out)]),patch.object(a.os,'sysconf',return_value=4096),\
     patch.object(a.context,'launch',side_effect=launch),patch.object(a.ledger,'Collector'),\
     patch.object(a.retention,'Collector'),patch.object(a.subprocess,'check_output',return_value=json.dumps(info).encode()),\
     patch.object(a.mappings,'supported',return_value=True),patch.object(a.ledger,'audit_snapshots',return_value=['complete']),\
     patch.object(a.retention,'audit_retention',return_value={'proof':'post-stop'}),\
     patch.object(a.retention,'add_load_comparisons'),patch.object(a,'audit_advice',return_value={'proof':'advice'}),\
     patch.object(a.verify,'validate_events',return_value=1919),patch.object(a.verify,'validate_engine_logs'),\
     patch.object(a.verify,'validate_report',side_effect=ValueError('active resource bound: rss')):
    self.assertEqual(a.main(),1)
   result=json.loads((out/'experiment.json').read_text());self.assertFalse(result['qualifies_24h'])
   self.assertEqual(result['status'],'failed');self.assertEqual(result['error'],'ValueError: active resource bound: rss')
   self.assertEqual(result['advice'],{'proof':'advice'});self.assertEqual(result['retention'],{'proof':'post-stop'})
   self.assertEqual(result['pilot']['snapshots'],['complete']);self.assertEqual(result['events'],1919)
   self.assertNotIn('acceptance',result)


if __name__=='__main__':unittest.main()
