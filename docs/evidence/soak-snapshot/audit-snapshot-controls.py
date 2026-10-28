"""Offline PR35 replay. Does not execute the archived probe or launcher."""
import argparse,gzip,hashlib,json,re,subprocess,sys,tempfile,zipfile
from pathlib import Path
PINS={'verify_soak.py':'e0c0321054c8be6510f190b33d07966aad8635aa','soak_build_pair.py':'25f981cf6fdf09b660d73273620834b149932839','soak_cycles.py':'9f48dda1f23035e856365f2fe9bdb138ed786f0e','soak_snapshot_compare.py':'c8ef8257f0ffbd4f6149caf46b3a37340c9c39fb','inventory_runtime_symbols.py':'050717ff98685312b5d740472393d2e428b97af3'}
ARCHIVES={'ordinary':'2bb064b836a9273074c4a534eea9b0ea68730c63c427d47d0974b69676c3d47b','race':'3722365efe2bf1f7f7378e2bae89fe5c3ad00ddb065449440e01208d746d63ce'}
CHECKOUT='b362c900b25935f39b3b8b271fc8664c4bde9a3c'
def sha(b):return hashlib.sha256(b).hexdigest()
def safe(s):return not Path(s).is_absolute() and '..' not in Path(s).parts
def files(root,entries):
 for f,h in entries.items():assert safe(f) and sha((root/f).read_bytes())==h,f
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('artifacts-dir','scripts-dir','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args()
 for n,h in PINS.items():
  b=(a.scripts_dir/n).read_bytes();assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==h,n
 sys.path.insert(0,str(a.scripts_dir.resolve()));import soak_cycles as c;import verify_soak as v
 jobs=[];events=maps=metadata=0
 for build,digest in ARCHIVES.items():
  archive=a.artifacts_dir/('snapshot-'+build+'.zip');assert sha(archive.read_bytes())==digest
  with tempfile.TemporaryDirectory() as t:
   root=Path(t)
   with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None and len(z.namelist())==len(set(z.namelist())) and all(safe(f) for f in z.namelist());z.extractall(root)
   original=json.loads((root/'comparison/snapshot-comparison.json').read_text());folder=root/'comparison';files(folder,original['files'])
   assert original['order']==['full','metadata_only','metadata_only','full'] and len(original['runs'])==4 and not original['qualifies_24h']
   info=original['build_info'];assert 'vcs.modified=false' in info and 'vcs.revision='+CHECKOUT in info and ('-race=true' in info)==(build=='race')
   binary_hash=sha((root/'binaries/probe').read_bytes());assert binary_hash==original['same_binary_sha256']
   for line in (root/'binary-sha256.txt').read_text().splitlines():
    h,f=line.split();assert sha((root/Path(f).relative_to('artifacts')).read_bytes())==h
   inv=json.loads((root/'symbols/inventory.json').read_text());assert inv['binary_sha256']==binary_hash and inv['description']['build_info']==info and not inv['truncated']
   nm=subprocess.check_output(['nm','-S','--defined-only',str(root/'binaries/probe')],text=True);assert nm==(root/'symbols/nm.txt').read_text()
   symbols={}
   for line in nm.splitlines():
    parts=line.split()
    if len(parts)==4:
     address,size,kind,name=parts;symbols[name]=(int(address,16),int(size,16),kind)
   candidates=[]
   for candidate in inv['candidates']:
    assert symbols[candidate['symbol']]==(candidate['address'],candidate['size'],candidate['type']) and candidate['size']>0
    asm=subprocess.check_output(['objdump','-d','--disassemble='+candidate['symbol'],str(root/'binaries/probe')],text=True)
    archived=(root/'symbols'/candidate['disassembly_file']).read_text()
    # Only the ELF filename header differs between the CI and temporary path.
    body=lambda s:s[s.index('Disassembly of section'):]
    assert body(asm)==body(archived)
    returns=[line for line in asm.splitlines() if re.search(r'\bret[q]?\b',line)]
    assert returns==candidate['return_instruction_lines'];candidates.append({'name':candidate['demangled'],'address':candidate['address'],'size':candidate['size'],'returns':len(returns)})
   assert len(candidates)==inv['candidate_count'];samples=[]
   for i,entry in enumerate(original['runs'],1):
    mode=entry['mapping_policy'];assert mode==original['order'][i-1] and entry['index']==i
    assert entry['host_thp_policy_before']==original['host_thp_policy']==entry['host_thp_policy_after']
    sample=folder/f'{i}-{mode}';saved=json.loads((sample/'cycles.json').read_text());files(sample,saved['files'])
    assert saved['mapping_policy']==mode and saved['thp_control']=='process' and not saved['qualifies_24h'] and len(saved['runs'])==1
    run=saved['runs'][0];assert run['binary_sha256']==binary_hash and run['build_info']==info and run['build']==build and run['exit_code']==0 and run['pid']==entry['pid']
    control=json.loads((sample/(build+'-control.json')).read_text());assert control==run['launcher_control']=={'pid':run['pid'],'before':0,'after':1}
    reports=[];errors=[];observations=[];previous=-1;details=[]
    for cycle in range(1,4):
     native=sample/build/f'cycle-{cycle}';r=json.loads((native/'report.json').read_text());reports.append(r);s=r['settings']
     assert r['build_info']==info and s['pid']==run['pid'] and s['diagnostic_mapping_policy']==mode
     assert (r['transport'],r['mode'],s['tls'],s['duration_seconds'],s['warmup_seconds'],s['sample_interval_seconds'],s['workers'],s['qps'],s['pool_min'],s['pool_max'],s['post_stop_observe_seconds'],s['diagnostic_go_scavenge'],s['diagnostic_cycles'],s['diagnostic_cycle_index'])==(3,1,1,180,12,5,2,10,16,64,120,True,3,cycle)
     assert not s.get('post_stop_observer_ack',False)
     for label,fn in [('report',lambda:v.validate_report(r,True)),('events',lambda:v.validate_events(native/'exchanges.jsonl.gz',r)),('logs',lambda:v.validate_engine_logs(native,sample/(build+'-stderr.log'),64,3))]:
      try:
       value=fn()
       if label=='events':assert value==1919;events+=value
      except (ValueError,KeyError,OSError,EOFError) as e:errors.append(f'cycle-{cycle} {label}: {e}')
     points=r['points']+r['post_stop_observation'];assert all(p['resources']['os_memory']['bytes']['AnonHugePages']==0 for p in points)
     records=[json.loads(line) for line in (native/'mapping-index.jsonl').read_text().splitlines()]
     L=len(r['points']);R=len(r['post_stop_observation']);expected=[(0,0)]+[(n,0) for n in range(1,L+1)]+[(L,n) for n in range(1,R+1)]+[(L,R)]
     assert [(x['load_points'],x['retention_points']) for x in records]==expected
     for record in records:
      assert record['mapping_policy']==mode and record['pid']==run['pid'] and record['cycle']==cycle and previous<=record['read_start_monotonic_ns']<=record['read_end_monotonic_ns'];previous=record['read_end_monotonic_ns']
      assert record['thp_enabled']=='0' and record['godebug']==''
      if mode=='full':
       assert safe(record['file']);raw=gzip.decompress((native/record['file']).read_bytes());assert sha(raw)==record['sha256_raw'];observations.append(dict(cycle=cycle,**c.thp_observation(raw.decode(),record,'process')));maps+=1
      else:
       assert 'file' not in record and 'sha256_raw' not in record and not list(native.glob('mapping-*.smaps.gz'));metadata+=1
       observations.append({'cycle':cycle,'anon_huge_bytes':None,'go_named_heap_huge_bytes':None,'scope':'metadata only; THP checked by target status and existing resource rollup, no full VMA sample'})
     post=r['post_stop_observation'];assert len(post)==26 and post[-2]['at_seconds']>=120 and post[-1]['phase']=='poststop_go_scavenge'
     details.append({'cycle':cycle,'records':len(records),'post_scavenge_rss':post[-1]['resources']['rss'],'post_scavenge_heap_alloc':post[-1]['resources']['heap_alloc']})
    fixed=c.fixed_envelope(reports);assert fixed==run['fixed_envelope']==entry['fixed_envelope'] and observations==run['thp_observations']==entry['thp_observations']
    # Separate arithmetic over raw samples, without calling the envelope helper.
    warm=[p['resources'] for p in reports[0]['points'] if p['phase']=='warmup' and p['at_seconds']>=6]
    for metric,allowance in v.ACTIVE.items():
     baseline=max(p[metric] for p in warm);assert baseline==fixed['baseline'][metric]
     for report,row in zip(reports,fixed['cycles']):
      measured=[p for p in report['points'] if p['phase']=='measured'];q=row['checks'][metric]
      violations=[{'at_seconds':p['at_seconds'],'value':p['resources'][metric]} for p in measured if not 0<p['resources'][metric]<=baseline+allowance]
      assert q=={'baseline':baseline,'peak':max(p['resources'][metric] for p in measured),'allowance':allowance,'violations':violations}
    if not fixed['passed']:errors.append('original first-cycle fixed active envelope exceeded')
    assert errors==run['errors']==entry['resource_errors']
    state='diagnostic_passed' if not errors else 'failed';assert saved['status']==state and entry['exit_code']==int(bool(errors)) and entry['errors']==([] if not errors else ['resource/evidence failure retained'])
    for row,detail in zip(fixed['cycles'],details):
     rss=row['checks']['rss'];detail.update({'baseline_rss':rss['baseline'],'peak_rss':rss['peak'],'rss_delta':rss['peak']-rss['baseline'],'rss_violations':len(rss['violations']),'other_active_failures':[k for k,q in row['checks'].items() if q['violations'] and k!='rss'],'return_failures':[k for k,q in row['local_resources']['return'].items() if not q['passed']]})
    samples.append({'index':i,'policy':mode,'pid':run['pid'],'status':state,'errors':errors,'cycles':details})
   state='diagnostic_passed' if all(not s['errors'] for s in samples) else 'failed';assert original['status']==state
   jobs.append({'build':build,'archive_sha256':digest,'binary_sha256':binary_hash,'launcher_sha256':sha((root/'binaries/thp-control').read_bytes()),'status':state,'candidates':candidates,'samples':samples})
 assert events==24*1919 and v.ACTIVE['rss']==67108864
 result={'audit_status':'independently_replayed','source_commit':'04df7573f508faf43e5cba47bed7be6fa7f0886d','checkout':CHECKOUT,'tree':'f14b24dd748cb8c63759f36e3ece498e75ba50b8','source_blobs':PINS,'events':events,'full_smaps':maps,'metadata_records':metadata,'qualifies_24h':False,'jobs':jobs,'limits':'Archived ELF bytes, nm symbols and candidate disassembly replayed without executing targets. Metadata-only omits full VMA samples; absent mappings are not zero. Does not prove runtime calls, allocator ownership, mapping generation, or uprobe safety. Report/rollup/logging overhead remains. Historical failures retained.'}
 a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ('audit_status','events','full_smaps','metadata_records')}))
if __name__=='__main__':main()
