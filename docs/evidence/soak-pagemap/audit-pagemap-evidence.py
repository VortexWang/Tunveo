"""Offline fixed-source replay of page status evidence; never executes targets."""
import argparse,gzip,hashlib,json,struct,sys,tempfile,zipfile
from pathlib import Path
from unittest.mock import patch
PINS={"audit_soak_os_memory.py":"0c5fbff721f98f94fb75f431da968679908d1171","audit_soak_retention.py":"3b06a71491258e62326f4d3d7f4dc4bdae10ca0b","soak_call_lifecycle.py":"0847600f9edce17e44de47e384a0992d54167828","soak_callsite_control.py":"ab76a87a1ebe6281b0372c6614f6a70aad8f7660","soak_mapping_ledger.py":"610a54d636767bf92752bd165b60faafd961c7be","soak_mapping_retention.py":"ae88355fbc1363aa3f60c45cb9e773544a07bf70","soak_mappings.py":"708301538c24476e4d244efb16cc5027c193efd5","soak_pagemap.py":"bc2cdbce1d52341b60d1e3d1eaa2e35172d79bb9","soak_ret_context.py":"eac5605150e51b9aec336277088e3981616ac28e","verify_soak.py":"e0c0321054c8be6510f190b33d07966aad8635aa"}
def sha(b):return hashlib.sha256(b).hexdigest()
def safe(n):return not Path(n).is_absolute() and '..' not in Path(n).parts
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for n in ('archive','scripts-dir','output'):ap.add_argument('--'+n,type=Path,required=True)
 ap.add_argument('--sha256',required=True);a=ap.parse_args();assert sha(a.archive.read_bytes())==a.sha256
 for n,pin in PINS.items():
  b=(a.scripts_dir/n).read_bytes();assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==pin,n
 sys.path.insert(0,str(a.scripts_dir.resolve()));import soak_pagemap as p
 with tempfile.TemporaryDirectory() as t:
  root=Path(t)
  with zipfile.ZipFile(a.archive) as z:
   assert z.testzip() is None and len(z.namelist())==len(set(z.namelist())) and all(safe(n) for n in z.namelist());z.extractall(root)
  exp=root/'experiment';saved=json.loads((exp/'experiment.json').read_text());assert saved['rss_budget']==p.life.verify.ACTIVE['rss']==67108864 and not saved['qualifies_24h']
  for n,h in saved['files'].items():assert safe(n) and sha((exp/n).read_bytes())==h,n
  for line in (root/'binary-sha256.txt').read_text().splitlines():
   h,n=line.split();assert sha((root/Path(n).relative_to('artifacts')).read_bytes())==h
  p.callsite.extract(root/'original-race.zip',root/'recovered-probe');assert (root/'recovered-probe').read_bytes()==(root/'binaries/probe').read_bytes()
  assert sha((root/'binaries/tracer').read_bytes())==(root/'tracer-binary.sha256').read_text().split()[0]
  info=(root/'bpftrace-info.txt').read_text();assert 'bfd: yes' in info and 'unsafe probe: no' in info
  assert (root/'tracer-source.txt').read_text().strip()=='93c593f6dab2e930d6198cfaa52b29d19a8c0647'
  result=dict(audit_status='independently_replayed',execution_source='a93ec401627bdc91cd1b6f84c0325695f1298968',source_blobs=PINS,archive_sha256=a.sha256,qualifies_24h=False,original_status=saved['status'],stages=[])
  totals=dict(events=0,checkpoints=0,status_vectors=0,page_entries=0)
  nm=__import__('subprocess').check_output(['nm','-S','--defined-only',str(root/'binaries/probe')],text=True);candidates=[]
  for line in nm.splitlines():
   fields=line.split()
   if len(fields)!=4:continue
   address,size,kind,symbol=fields
   if kind in ('T','t','W','w') and symbol.startswith('_Z') and ('MmapAlignedOrDieOnFatalError' in symbol or ('SizeClassAllocator32' in symbol and 'AP32' in symbol and 'AllocateBatch' in symbol)):
    address=int(address,16);size=int(size,16);offset=p.callsite.file_offset(root/'binaries/probe',address,size)
    name=__import__('subprocess').check_output(['c++filt',symbol],text=True).strip()
    candidates.append(dict(symbol=symbol,demangled=name,address=address,size=size,file_offset=offset,bytes_sha256=sha((root/'binaries/probe').read_bytes()[offset:offset+size]),qualification='static candidate only; actual execution and association with 2MiB requests unverified'))
  result['static_next_call_candidates']=candidates
  elf=(root/'binaries/probe').read_bytes();phoff=struct.unpack_from('<Q',elf,32)[0];entsize,nph=struct.unpack_from('<HH',elf,54);zero_ranges=[]
  for i in range(nph):
   typ,perm,off,va,_,file_size,mem_size,align=struct.unpack_from('<IIQQQQQQ',elf,phoff+i*entsize)
   if typ==1 and mem_size>file_size:zero_ranges.append(dict(start=(va+file_size+4095)//4096*4096,end=(va+mem_size+4095)//4096*4096,p_vaddr=va,p_filesz=file_size,p_memsz=mem_size,flags=perm))
  result['ELF_zero_fill_full_page_ranges']=zero_ranges
  for name in ('control-disabled','control-enabled','15s','180s'):
   folder=exp/name
   if not folder.exists():result['stages'].append(dict(stage=name,status='not_started'));continue
   control=name.startswith('control-');binary=root/'binaries'/('control' if control else 'probe');plan=json.loads((folder/'plan.json').read_text());run=json.loads((folder/'execution.json').read_text())
   assert plan['binary_sha256']==sha(binary.read_bytes()) and run['exit_code']==0 and not run['timed_out'] and run['group_gone'] and not run['cleanup_signals'] and run['target_identity_verified']
   for k,f in [('target_identity','target-before.stat'),('tracer_identity','tracer-before.stat')]:assert p.life.context.proc_identity((folder/f).read_text())==run[k]
   assert p.life.context.owned_groups(run['process_group'],run['target_identity'],run['tracer_identity'],(folder/'tracer-exe.txt').read_text(),Path(run['command'][2]))==run['owned_groups']
   assert not (folder/'bpftrace-stderr.log').read_text()
   local=p.life.context.plan(binary,{int(k):f['symbol'] for k,f in plan['functions'].items()})
   def norm(f):
    d=dict(f);s=d['disassembly'];d['disassembly']=s[s.index('Disassembly of section'):];return d
   assert {k:norm(f) for k,f in local['functions'].items()}=={k:norm(f) for k,f in plan['functions'].items()}
   site=p.callsite.call_site(local)
   with patch.object(p.callsite,'call_site',return_value=site):
    assert p.life.program(plan)==(folder/'program.bt').read_text()
    parsed=json.loads(json.dumps(p.life.parse((folder/'events.log').read_text(),plan,run['expected_uid'])))
   assert parsed==json.loads((folder/'context-audit.json').read_text())==saved[name]['ledger']
   vm=p.life.snapshots(folder,parsed,control);pages=p.analyze(folder,parsed)
   assert json.loads(json.dumps(vm))==saved[name]['snapshots'] and pages==saved[name]['pages']
   index=json.loads((folder/'page-status-index.json').read_text());assert len(index['records'])==len(pages)==len(vm) and index['PFNs_saved'] is False
   entries=vectors=0
   for raw_record,row in zip(index['records'],pages):
    for r,q in zip(raw_record['ranges'],row['ranges']):
     assert r['pages']==(r['end']-r['start'])//4096
     for file_key,stat_key in [('first_file','first'),('second_file','second')]:
      data=gzip.decompress((folder/r[file_key]).read_bytes());assert len(data)==r['pages']*2
      values=[x[0] for x in struct.iter_unpack('<H',data)];assert all(x<512 and x&384!=384 for x in values)
      assert sum(bool(x&256) for x in values)==q[stat_key]['present_pages'] and sum(bool(x&128) for x in values)==q[stat_key]['swapped_pages']
      vectors+=1;entries+=len(values)
     assert sum(x['pages'] for x in q['by_origin'].values())==r['pages']
     assert sum(x['present_first'] for x in q['by_origin'].values())==q['first']['present_pages'] and sum(x['present_second'] for x in q['by_origin'].values())==q['second']['present_pages']
     known=q['by_origin'].get(p.life.LABEL,{})
     assert sum(x['pages'] for x in q['by_generation'].values())==known.get('pages',0)
   summary=dict(stage=name,native_pid=parsed['native_pid'],events=parsed['events'],call_count=len(parsed['call_proof']['calls']),checkpoints=len(pages),status_vectors=vectors,page_entries=entries,selected=[],errors=[])
   if control:
    mode=name.split('-')[1];p.validate_control(folder,parsed,vm,pages,mode)
    base=vm[0]['point']['base'];held=next(r for r in pages if r['key']=='held');zero=next(r for r in pages if r['key']=='read_zero')
    z=next(r for r in zero['ranges'] if (r['start'],r['end'])==(base,base+4*1024*1024))
    assert z['first']['present_pages']==z['second']['present_pages']==1024 and z['smaps_rss']==0
    raw=gzip.open(folder/held['source_smaps_file'],'rt').read();summary['held_anon_huge_bytes']=p.huge(raw,base,base+4*1024*1024)
    if mode=='enabled':assert summary['held_anon_huge_bytes']>=2*1024*1024
    else:assert summary['held_anon_huge_bytes']==0
    summary['read_zero_present_pages']=1024;summary['read_zero_smaps_rss']=0
   else:
    report=json.loads((folder/'native/report.json').read_text());assert report['settings']['pid']==parsed['native_pid'] and 'vcs.revision='+p.callsite.REVISION in report['build_info']
    n=p.life.verify.validate_events(folder/'native/exchanges.jsonl.gz',report);assert n==saved[name]['events'];summary['business_events']=n
    p.life.verify.validate_engine_logs(folder/'native',folder/'native-stderr.log',64,3)
    errors=[]
    try:resources=p.life.verify.validate_report(report,True);assert resources==saved[name]['resources']
    except ValueError as e:errors.append(str(e))
    assert errors==saved[name]['errors'];summary['errors']=errors
    warm=[q for q in report['points'] if q['phase']=='warmup' and q['at_seconds']>=6];measured=[q for q in report['points'] if q['phase']=='measured'];peak=max(measured,key=lambda q:q['resources']['rss']);baseline=max(q['resources']['rss'] for q in warm)
    summary['quality']=dict(max_capture_ns=max(q['page_finished_ns']-q['page_started_ns'] for q in index['records']),added_vmas=sum(len(q['added_vmas']) for q in pages),topology_changed_ranges=sum(not v['topology_unchanged'] for q in pages for v in q['ranges']),residency_changed_entries=sum(v['residency_changed'] for q in pages for v in q['ranges']))
    summary['rss']=dict(baseline=baseline,peak=peak['resources']['rss'],delta=peak['resources']['rss']-baseline,violations=sum(not 0<q['resources']['rss']<=baseline+67108864 for q in measured),measured_points=len(measured))
    for metric,limit in p.life.verify.ACTIVE.items():
     if metric!='rss':assert all(0<q['resources'][metric]<=max(w['resources'][metric] for w in warm)+limit for q in measured)
    for metric,limit in p.life.verify.RETURN.items():assert 0<report['after_stop'][metric]<=report['idle_baseline'][metric]+limit
    baseline_point=max(warm,key=lambda q:q['resources']['rss']);chosen=[[baseline_point['phase'],baseline_point['at_seconds']],[peak['phase'],peak['at_seconds']]];post=report.get('post_stop_observation',[])
    if post:chosen+=[[post[0]['phase'],post[0]['at_seconds']],[post[-2]['phase'],post[-2]['at_seconds']],[post[-1]['phase'],post[-1]['at_seconds']]]
    for key in chosen:
     page=next(r for r in pages if r['key']==key);source=next(r for r in vm if r['key']==key);by={}
     for r in page['ranges']:
      for label,numbers in r['by_origin'].items():
       dest=by.setdefault(label,dict(pages=0,present_first=0,present_second=0,swapped_first=0,swapped_second=0))
       for k,v in numbers.items():dest[k]+=v
     item=dict(key=key,native_rss=source['point']['resources']['rss'],page_started_ns=page['page_started_ns'],page_finished_ns=page['page_finished_ns'],by_origin=by,added_vmas=len(page['added_vmas']),entries_changed=sum(r['entries_changed'] for r in page['ranges']),residency_changed=sum(r['residency_changed'] for r in page['ranges']),scope='present/swapped counts, not RSS/PSS or physical exclusive bytes')
     selected_record=next(q for q in index['records'] if q['key']==key);image=[]
     for q in selected_record['ranges']:
      if any(z['start']<=q['start']<q['end']<=z['end'] for z in zero_ranges):
       aa=p.flags(folder/q['first_file'],q['pages']);bb=p.flags(folder/q['second_file'],q['pages']);image.append(dict(start=q['start'],end=q['end'],present_first=sum(bool(x&256) for x in aa),present_second=sum(bool(x&256) for x in bb),scope='ELF zero-fill address match, not writer/object attribution'))
     item['ELF_zero_fill_address_matches']=image
     if key[0]=='poststop_go_scavenge':
      record=selected_record;start=record['page_started_ns'];end=record['page_finished_ns'];before=p.life.replay(parsed['calls'],start);after=p.life.replay(parsed['calls'],end);bs=[q[0] for q in before];fs=[q[0] for q in after]
      overlap=p.union([bounds for c in parsed['calls'] if c['start_ns']<=end and c['end_ns']>=start for bounds in p.life.affected(c)]);us=[q[0] for q in overlap];groups={};untracked={};call_by_id={c['id']:c for c in parsed['calls']}
      for q in record['ranges']:
       first=p.flags(folder/q['first_file'],q['pages']);second=p.flags(folder/q['second_file'],q['pages'])
       for i,(fa,fb) in enumerate(zip(first,second)):
        lo=q['start']+i*4096
        if p.page_origin(lo,before,after,bs,fs,overlap,us,q['topology_unchanged'])[0]==p.life.LABEL:continue
        left=p.at_page(lo,before,bs);right=p.at_page(lo,after,fs);u=__import__('bisect').bisect_right(us,lo+4095)-1;changing=u>=0 and overlap[u][1]>lo
        gen=left[1] if q['topology_unchanged'] and not changing and left==right and left[0]=='unresolved' and left[1] is not None else 'no_stable_generation'
        dest=groups.setdefault(gen,dict(generation=gen,pages=0,present_first=0,present_second=0));dest['pages']+=1;dest['present_first']+=bool(fa&256);dest['present_second']+=bool(fb&256)
        if gen=='no_stable_generation':
         key2=(q['start'],q['end']);v=untracked.setdefault(key2,dict(start=q['start'],end=q['end'],pages=0,present_first=0,present_second=0));v['pages']+=1;v['present_first']+=bool(fa&256);v['present_second']+=bool(fb&256)
      ranked=sorted(groups.values(),key=lambda q:q['present_second'],reverse=True)
      for q in ranked:
       q['surviving_virtual_bytes_at_page_end']=sum(b-a for a,b,owner,gen in after if gen==q['generation']) if q['generation']!='no_stable_generation' else None
       c=call_by_id.get(q['generation']);q['creation_request']=({k:c[k] for k in ('call','tid','id','start_ns','end_ns','args','value','owner')} if c else None)
      assert sum(q['present_second'] for q in ranked)==by.get('unresolved',{}).get('present_second',0)
      item['unresolved_by_stable_creation_generation']=ranked
      for v in untracked.values():v['bounds_within_ELF_zero_fill_tail']=any(z['start']<=v['start']<v['end']<=z['end'] for z in zero_ranges)
      item['untracked_regions']=list(untracked.values())
     summary['selected'].append(item)
   result['stages'].append(summary);totals['events']+=parsed['events'];totals['checkpoints']+=len(pages);totals['status_vectors']+=vectors;totals['page_entries']+=entries
  result['totals']=totals;result['limits']='Pinned executable parser replay plus independent status-bit/count conservation. No archived binary execution. Status-only two reads are not atomic; no PFNs, no object lifecycle, no page-count-to-RSS conversion, no new observation overhead control or 24h qualification.'
  a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
