"""Independent fixed-source replay of PR34; never runs native programs."""
import argparse,gzip,hashlib,json,sys,tempfile,zipfile,re
from pathlib import Path
PINS={'verify_soak.py':'e0c0321054c8be6510f190b33d07966aad8635aa','soak_build_pair.py':'25f981cf6fdf09b660d73273620834b149932839','soak_cycles.py':'9db96b8d53390775d3b845a7675bf5dc41cb9943','soak_thp_compare.py':'f728104166fd32c4c880d65eccfde445d3bf840b'}
ARCHIVES={'thp-race-process.zip':'995436a915b9dba529ec16ea36f7e4699697cff0a56e88793ea8b0e88bc1c49c','thp-ordinary-process.zip':'e5f9259b7470590fc8f76a9183b16fba7fa83df789b6fdca9dee0b7b609dfd7d','thp-ordinary-go_heap.zip':'94b30eec7df4b1e3e9fc6fd4474a0a0db39c1a500dfeb6f39ddbb0e2ebc17d81','thp-race-go_heap.zip':'003f3a4f1f9c6edadb57ad320b6ef58723f580150cadccd529f5b897b207f6b9'}
CHECKOUT='30b69a5b28f17937569dacb56148b651b180b042'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def safe(s):return not Path(s).is_absolute() and '..' not in Path(s).parts
def files(root,m):
 for path,h in m.items():assert safe(path) and sha(root/path)==h,path

def address_groups(raw,race):
 groups={};category=None
 for line in raw.splitlines():
  m=re.fullmatch(r'([0-9a-f]+)-([0-9a-f]+)\s+\S+\s+\S+\s+\S+\s+\d+\s*(.*)',line)
  if m:
   lo,hi=int(m[1],16),int(m[2],16);name=m[3];category=name or 'unnamed_other'
   if name.startswith('/'):category='file'
   if race and not name:
    if 0x200000000000<=lo<hi<=0x21c000000000:category='race_shadow_band'
    if 0x300000000000<=lo<hi<=0x400000000000:category='race_metadata_band'
  else:
   m=re.fullmatch(r'Rss:\s+(\d+) kB',line)
   if m:
    assert category is not None
    groups[category]=groups.get(category,0)+int(m[1])*1024
 return groups

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('artifacts-dir','scripts-dir','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args()
 for name,pin in PINS.items():
  b=(a.scripts_dir/name).read_bytes();assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==pin,name
 sys.path.insert(0,str(a.scripts_dir.resolve()));import soak_cycles as c;import verify_soak as v
 jobs=[];total_events=0;total_maps=0
 for archive,digest in ARCHIVES.items():
  path=a.artifacts_dir/archive;assert sha(path)==digest
  with tempfile.TemporaryDirectory(prefix='pr34-replay-') as t:
   unpacked=Path(t)
   with zipfile.ZipFile(path) as z:
    assert z.testzip() is None and len(z.namelist())==len(set(z.namelist())) and all(safe(n) for n in z.namelist());z.extractall(unpacked)
   root=unpacked/archive.removeprefix('thp-').removesuffix('.zip');original=json.loads((root/'comparison.json').read_text());files(root,original['files'])
   kind=original['control'];build=original['build'];assert original['order']==['baseline',kind,kind,'baseline'] and len(original['runs'])==4 and not original['qualifies_24h']
   info=original['build_info'];assert 'vcs.modified=false' in info and 'vcs.revision='+CHECKOUT in info and ('-race=true' in info)==(build=='race')
   policy=original['host_thp_policy'];samples=[]
   for i,entry in enumerate(original['runs'],1):
    mode=entry['mode'];assert mode==original['order'][i-1] and entry['index']==i and entry['host_thp_policy_before']==policy==entry['host_thp_policy_after']
    folder=root/f'{i}-{mode}';saved=json.loads((folder/'cycles.json').read_text());files(folder,saved['files']);assert saved['thp_control']==mode and len(saved['runs'])==1 and not saved['qualifies_24h']
    run=saved['runs'][0];assert run['build']==build and run['build_info']==info and run['binary_sha256']==original['same_binary_sha256'] and run['exit_code']==0 and run['pid']==entry['native_pid']
    control=json.loads((folder/(build+'-control.json')).read_text());assert control==run['launcher_control']=={'pid':run['pid'],'before':0,'after':int(mode=='process')}
    reports=[];errors=[];observations=[];previous=-1;cycle_summary=[]
    for cycle in range(1,4):
     native=folder/build/f'cycle-{cycle}';report=json.loads((native/'report.json').read_text());reports.append(report)
     s=report['settings'];assert report['build_info']==info and s['pid']==run['pid']
     assert (report['transport'],report['mode'],s['tls'],s['duration_seconds'],s['warmup_seconds'],s['sample_interval_seconds'],s['workers'],s['qps'],s['pool_min'],s['pool_max'],s['post_stop_observe_seconds'],s['diagnostic_go_scavenge'],s['diagnostic_cycles'],s['diagnostic_cycle_index'])==(3,1,1,180,12,5,2,10,16,64,120,True,3,cycle)
     assert not s.get('post_stop_observer_ack',False)
     for label,fn in [('report',lambda:v.validate_report(report,True)),('events',lambda:v.validate_events(native/'exchanges.jsonl.gz',report)),('logs',lambda:v.validate_engine_logs(native,folder/(build+'-stderr.log'),64,3))]:
      try:
       value=fn()
       if label=='events':assert value==1919;total_events+=value
      except (ValueError,KeyError,OSError,EOFError) as e:errors.append(f'cycle-{cycle} {label}: {e}')
     records=[json.loads(x) for x in (native/'mapping-index.jsonl').read_text().splitlines()]
     expected=[(0,0)]+[(n,0) for n in range(1,len(report['points'])+1)]+[(len(report['points']),n) for n in range(1,len(report['post_stop_observation'])+1)]+[(len(report['points']),len(report['post_stop_observation']))]
     assert [(r['load_points'],r['retention_points']) for r in records]==expected
     assert records[-1]['load_points']==len(report['points']) and records[-1]['retention_points']==len(report['post_stop_observation'])
     obs=[];post_groups=None;post_record=None
     for record in records:
      assert record['pid']==run['pid'] and record['cycle']==cycle and previous<=record['read_start_monotonic_ns']<=record['read_end_monotonic_ns'];previous=record['read_end_monotonic_ns']
      assert safe(record['file']);raw=gzip.decompress((native/record['file']).read_bytes());assert hashlib.sha256(raw).hexdigest()==record['sha256_raw']
      o=dict(cycle=cycle,**c.thp_observation(raw.decode(),record,mode));observations.append(o);obs.append(o);total_maps+=1
      if record['retention_points']==len(report['post_stop_observation']) and record['status']=='running' and post_groups is None:
       post_groups=address_groups(raw.decode(),build=='race');post_record=record
     post=report['post_stop_observation'];assert len(post)==26 and post[-2]['at_seconds']>=120 and post[-1]['phase']=='poststop_go_scavenge'
     end=post[-1]['resources'];assert post_groups is not None;cycle_summary.append({'post_scavenge_snapshot_groups':post_groups,'post_scavenge_mapping_record':post_record,'cycle':cycle,'post_scavenge_rss':end['rss'],'post_scavenge_anon_huge':end['os_memory']['bytes']['AnonHugePages'],'post_scavenge_heap_alloc':end['heap_alloc'],'maximum_observed_anon_huge':max(o['anon_huge_bytes'] for o in obs),'maximum_observed_go_heap_huge':max(o['go_named_heap_huge_bytes'] for o in obs)})
    fixed=c.fixed_envelope(reports);assert fixed==run['fixed_envelope']==entry['fixed_envelope'] and observations==run['thp_observations']==entry['thp_observations']
    if not fixed['passed']:errors.append('original first-cycle fixed active envelope exceeded')
    assert errors==run['errors']==entry['resource_errors']
    state='diagnostic_passed' if not errors else 'failed';assert saved['status']==state and entry['exit_code']==int(bool(errors))
    assert entry['errors']==([] if not errors else ['resource or evidence validation failed; original failure retained'])
    for row,detail in zip(fixed['cycles'],cycle_summary):
     rss=row['checks']['rss'];detail.update({'baseline_rss':rss['baseline'],'peak_rss':rss['peak'],'rss_delta':rss['peak']-rss['baseline'],'rss_violations':len(rss['violations']),'other_active_failures':[k for k,q in row['checks'].items() if q['violations'] and k!='rss'],'return_failures':[k for k,q in row['local_resources']['return'].items() if not q['passed']]})
    samples.append({'index':i,'mode':mode,'pid':run['pid'],'status':state,'errors':errors,'cycles':cycle_summary})
   exposure='maximum_observed_go_heap_huge' if kind=='go_heap' else 'maximum_observed_anon_huge'
   assert all(max(c[exposure] for c in sample['cycles'])>0 for sample in samples if sample['mode']=='baseline')
   assert policy and any(k.endswith('/enabled') for k in policy)
   state='diagnostic_passed' if all(not s['errors'] for s in samples) else 'failed';assert state==original['status']
   jobs.append({'archive':archive,'sha256':digest,'build':build,'control':kind,'original_status':state,'kernel':original['kernel'],'host_thp_policy':policy,'samples':samples})
  print('replayed',archive,flush=True)
 result={'audit_status':'independently_replayed','source_commit':'8a50a5e5b7d1f0bd33bed98615f859ea7e9ff82b','checkout':CHECKOUT,'source_blobs':PINS,'audited_events':total_events,'audited_smaps':total_maps,'qualifies_24h':False,'jobs':jobs,'limits':'Native/launcher binaries were not archived: recorded binary hash equality and source/target-state evidence are checked, not reconstructed binary bytes. No mapping generations or object callers; THP is a subset of RSS, not additive. Interventions cannot replace original acceptance.'}
 assert total_events==48*1919 and total_maps>=48*68 and v.ACTIVE['rss']==67108864
 a.output.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'audit_status':result['audit_status'],'events':total_events,'smaps':total_maps,'jobs':[(j['build'],j['control'],j['original_status']) for j in jobs]}))
if __name__=='__main__':main()
