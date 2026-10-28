"""Fixed-source, offline PR38 replay. Never executes archived binaries."""
import argparse,hashlib,json,sys,tempfile,zipfile
from pathlib import Path
from unittest.mock import patch
PINS={"audit_soak_os_memory.py":"0c5fbff721f98f94fb75f431da968679908d1171","audit_soak_retention.py":"3b06a71491258e62326f4d3d7f4dc4bdae10ca0b","soak_call_lifecycle.py":"0847600f9edce17e44de47e384a0992d54167828","soak_callsite_control.py":"ab76a87a1ebe6281b0372c6614f6a70aad8f7660","soak_mapping_ledger.py":"610a54d636767bf92752bd165b60faafd961c7be","soak_mapping_retention.py":"1796b76f75a35c0b6245350244e260efae53345b","soak_mappings.py":"708301538c24476e4d244efb16cc5027c193efd5","soak_ret_context.py":"eac5605150e51b9aec336277088e3981616ac28e","verify_soak.py":"e0c0321054c8be6510f190b33d07966aad8635aa"}
def sha(b):return hashlib.sha256(b).hexdigest()
def safe(p):return not Path(p).is_absolute() and '..' not in Path(p).parts
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('archive','scripts-dir','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--sha256',required=True);a=p.parse_args()
 assert sha(a.archive.read_bytes())==a.sha256
 for n,pin in PINS.items():
  b=(a.scripts_dir/n).read_bytes();assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==pin,n
 sys.path.insert(0,str(a.scripts_dir.resolve()));import soak_call_lifecycle as l
 with tempfile.TemporaryDirectory() as t:
  root=Path(t)
  with zipfile.ZipFile(a.archive) as z:
   assert z.testzip() is None and len(z.namelist())==len(set(z.namelist())) and all(safe(n) for n in z.namelist());z.extractall(root)
  folder=root/'experiment';saved=json.loads((folder/'experiment.json').read_text())
  for n,h in saved['files'].items():assert safe(n) and sha((folder/n).read_bytes())==h,n
  for line in (root/'binary-sha256.txt').read_text().splitlines():
   h,n=line.split();assert sha((root/Path(n).relative_to('artifacts')).read_bytes())==h
  l.callsite.extract(root/'original-race.zip',root/'recovered-probe');assert (root/'recovered-probe').read_bytes()==(root/'binaries/probe').read_bytes()
  assert (root/'binaries/tracer').is_file()
  recorded=(root/'tracer-binary.sha256').read_text().split()[0];assert sha((root/'binaries/tracer').read_bytes())==recorded
  assert (root/'tracer-source.txt').read_text().strip()=='93c593f6dab2e930d6198cfaa52b29d19a8c0647'
  info=(root/'bpftrace-info.txt').read_text();assert 'bfd: yes' in info and 'unsafe probe: no' in info
  summaries=[];all_errors=[];total_events=total_snapshots=0
  for stage in ('control','15s','180s'):
   f=folder/stage
   if not f.exists():
    summaries.append({'stage':stage,'state':'not_started'});continue
   plan=json.loads((f/'plan.json').read_text());run=json.loads((f/'execution.json').read_text());binary=root/'binaries'/('control' if stage=='control' else 'probe')
   assert plan['binary_sha256']==sha(binary.read_bytes()) and run['exit_code']==0 and not run['timed_out'] and run['group_gone'] and not run['cleanup_signals'] and run['target_identity_verified']
   for key,n in [('target_identity','target-before.stat'),('tracer_identity','tracer-before.stat')]:assert l.context.proc_identity((f/n).read_text())==run[key]
   assert l.context.owned_groups(run['process_group'],run['target_identity'],run['tracer_identity'],(f/'tracer-exe.txt').read_text(),Path(run['command'][2]))==run['owned_groups']
   assert not (f/'bpftrace-stderr.log').read_text()
   local=l.context.plan(binary,{int(k):v['symbol'] for k,v in plan['functions'].items()})
   def norm(v):
    d=dict(v);s=d['disassembly'];d['disassembly']=s[s.index('Disassembly of section'):];return d
   assert {k:norm(v) for k,v in local['functions'].items()}=={k:norm(v) for k,v in plan['functions'].items()}
   site=l.callsite.call_site(local)
   with patch.object(l.callsite,'call_site',return_value=site):
    assert l.program(plan)==(f/'program.bt').read_text()
    parsed=json.loads(json.dumps(l.parse((f/'events.log').read_text(),plan,run['expected_uid'])))
   assert parsed==json.loads((f/'context-audit.json').read_text())
   assert parsed['native_pid']==run['target_identity']['pid']
   rows=l.snapshots(f,parsed,stage=='control');assert json.loads(json.dumps(rows))==saved[stage]['snapshots'] and parsed==saved[stage]['ledger']
   if stage=='control':
    l.validate_control(f,parsed,rows)
    base=rows[0]['point']['base'];M=1024*1024;known=parsed['call_proof']['calls']
    assert len(known)==1 and known[0]['size']==4*M and known[0]['pointer']==base
    assert all(r['point']['base']==base for r in rows)
    output=json.loads((f/'native-stdout.log').read_text());assert output['status']=='passed' and output['base']==base and output['moved']==rows[-1]['point']['current']
    for row in rows:
     phase=row['key'];current=row['point']['current']
     if phase in ('held','discarded','failed_advice','retouched'):
      vmas=[v for v in row['unnamed_vmas'] if v['start']<base+4*M and base<v['end']]
      assert len(vmas)==1 and (vmas[0]['start'],vmas[0]['end'])==(base,base+4*M)
      assert vmas[0]['rss']==(0 if phase in ('discarded','failed_advice') else 4*M)
     if phase in ('hole','moved'):assert not any(v['start']<base+3*M and base+M<v['end'] for v in row['unnamed_vmas'])
     if phase=='moved':
      vmas=[v for v in row['unnamed_vmas'] if v['start']<current+4*M and current<v['end']]
      assert len(vmas)==1 and (vmas[0]['start'],vmas[0]['end'],vmas[0]['rss'])==(current,current+4*M,4*M)
     if phase=='released':assert not any(v['start']<current+4*M and current<v['end'] for v in row['unnamed_vmas'])
   # Explicit independent interval invariants over each saved checkpoint.
   for row in rows:
    state=l.replay(parsed['calls'],row['read_start_ns'])
    assert all(a<b for a,b,_,_ in state) and all(x[1]<=y[0] for x,y in zip(state,state[1:]))
    for v in row['unnamed_vmas']:
     if v['request_path']==l.LABEL:assert v['generations'] and not v['overlapping_operation'] and l.cover(v['start'],v['end'],state)==(l.LABEL,v['generations'])
    assert sum(row['groups_rss_bytes'].values())>=sum(v['rss'] for v in row['unnamed_vmas'])
   proof=parsed['call_proof'];total_events+=parsed['events'];total_snapshots+=len(rows)
   summary={'stage':stage,'native_pid':parsed['native_pid'],'events':parsed['events'],'call_count':len(proof['calls']),'cumulative_virtual_requested':sum(c['size'] for c in proof['calls']),'memory_calls':dict(__import__('collections').Counter(c['call'] for c in parsed['calls'])),'ambiguous_calls':sum(c['ambiguous'] for c in parsed['calls']),'snapshots':len(rows),'selected':[],'errors':[]}
   if stage!='control':
    r=json.loads((f/'native/report.json').read_text());assert r['settings']['pid']==parsed['native_pid'] and 'vcs.revision='+l.callsite.REVISION in r['build_info'] and 'vcs.modified=false' in r['build_info']
    assert r['settings']['duration_seconds']==int(stage[:-1]) and r['settings']['warmup_seconds']==12
    n=l.verify.validate_events(f/'native/exchanges.jsonl.gz',r);assert n==saved[stage]['events'];summary['business_events']=n
    l.verify.validate_engine_logs(f/'native',f/'native-stderr.log',64,3)
    errors=[]
    try:resources=l.verify.validate_report(r,True);assert resources==saved[stage]['resources']
    except ValueError as e:errors.append(str(e))
    assert errors==saved[stage]['errors'];summary['errors']=errors;all_errors+=errors
    warm=[p for p in r['points'] if p['phase']=='warmup' and p['at_seconds']>=6];measured=[p for p in r['points'] if p['phase']=='measured'];baseline=max(p['resources']['rss'] for p in warm);peak=max(measured,key=lambda p:p['resources']['rss'])
    summary['rss']={'baseline':baseline,'peak':peak['resources']['rss'],'delta':peak['resources']['rss']-baseline,'violations':sum(not 0<p['resources']['rss']<=baseline+67108864 for p in measured),'measured_points':len(measured)}
    summary['all_active']={}
    for metric,limit in l.verify.ACTIVE.items():
     base=max(p['resources'][metric] for p in warm);high=max(p['resources'][metric] for p in measured);violations=sum(not 0<p['resources'][metric]<=base+limit for p in measured)
     summary['all_active'][metric]={'baseline':base,'peak':high,'allowance':limit,'violations':violations}
     if metric!='rss':assert violations==0
    summary['return']={}
    for metric,limit in l.verify.RETURN.items():
     base=r['idle_baseline'][metric];after=r['after_stop'][metric];assert 0<after<=base+limit
     summary['return'][metric]={'baseline':base,'after_stop':after,'allowance':limit,'passed':True}
    chosen=[[peak['phase'],peak['at_seconds']]]
    post=r.get('post_stop_observation',[])
    if post:
     assert stage=='180s' and r['settings']['post_stop_observe_seconds']==120 and r['settings']['diagnostic_go_scavenge'] and r['settings']['post_stop_observer_ack']
     chosen += [[post[0]['phase'],post[0]['at_seconds']],[post[-2]['phase'],post[-2]['at_seconds']],[post[-1]['phase'],post[-1]['at_seconds']]]
    for key in chosen:
     row=next(x for x in rows if x['key']==key)
     state=l.replay(parsed['calls'],row['read_start_ns']);bands=__import__('collections').Counter()
     for v in row['unnamed_vmas']:
      if v['request_path']=='unresolved':bands[v['address_category']]+=v['rss']
     summary['selected'].append({'key':key,'rss':row['point']['resources']['rss'],'heap_alloc':row['point']['resources']['heap_alloc'],'groups_rss_bytes':row['groups_rss_bytes'],'unresolved_by_address_category':dict(bands),'validated_virtual_mapped_bytes':sum(b-a for a,b,owner,gen in state if owner==l.LABEL),'validated_path_vmas':[v for v in row['unnamed_vmas'] if v['request_path']==l.LABEL]})
   summaries.append(summary)
  assert saved['rss_budget']==l.verify.ACTIVE['rss']==67108864 and not saved['qualifies_24h']
  result={'audit_status':'independently_replayed','execution_source':'1ec8bfe38f53312d9349b7698f49c8eecb2cca91','archive_sha256':a.sha256,'source_blobs':PINS,'native_elf_sha256':l.callsite.BINARY_SHA,'tracer_elf_sha256':recorded,'original_status':saved['status'],'stages':summaries,'events':total_events,'snapshots':total_snapshots,'qualifies_24h':False,'scope':'Raw events and ELF/offset/identity/point/hash evidence replayed offline; call-only projection explicit and original IDs retained. Whole-VMA request lineage only, not object or absence-of-leak proof. Snapshot comparator uses pinned executable logic plus independent interval/coverage invariants. No native targets or tracer executed by this audit.'}
  a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
