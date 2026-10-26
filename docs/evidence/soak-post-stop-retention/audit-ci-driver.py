from pathlib import Path
import sys,json,zipfile,hashlib,re,gzip
root=Path('/workspace/scratch/0db146b59a43/Tunveo');sys.path.insert(0,str(root/'scripts'));import verify_soak as v;import soak_mappings as m;import audit_soak_retention as a;import audit_soak_os_memory as os
base=root/'artifacts/post-stop-retention'

def audit_set(metadata_name,tag):
 meta=json.loads((base/metadata_name).read_text());out={}
 for item in meta['artifacts']['artifacts']:
  mode='race' if item['name'].endswith('-race') else 'ordinary';suffix='-ack' if tag=='ack' else ''
  z=base/'ci-zips'/f'{item["name"]}{suffix}.zip'
  assert z.stat().st_size==item['size_in_bytes'] and 'sha256:'+hashlib.sha256(z.read_bytes()).hexdigest()==item['digest']
  dest=base/f'audit-{tag}-{mode}'
  with zipfile.ZipFile(z) as f:
   assert f.testzip() is None and all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in f.namelist());f.extractall(dest)
  folder=dest/'window';s=json.loads((folder/'pilot/summary.json').read_text());r=json.loads((folder/'pilot/native/report.json').read_text());c=json.loads((folder/'mapping-report.json').read_text())
  assert meta['checkout'] in r['build_info'] and 'vcs.modified=false' in r['build_info'] and ('-race=true' in r['build_info'])==(mode=='race')
  assert c['binary_sha256']==s['binary_sha256']==(dest/'binary.sha256').read_text().split()[0]
  for f,sha in s['files'].items():assert hashlib.sha256((folder/'pilot'/f).read_bytes()).hexdigest()==sha
  assert s['exit_code']==0 and s['cleanup']['reaped'] and not s['cleanup']['forced_kill'] and s['pilot'] and not s['qualifies_24h']
  error=None
  try:v.validate_report(r,True)
  except ValueError as e:error='ValueError: '+str(e)
  assert (s['status']=='pilot_passed')==(error is None) and s.get('error')==error
  events=v.validate_events(folder/'pilot/native/exchanges.jsonl.gz',r);v.validate_engine_logs(folder/'pilot/native',folder/'pilot/stderr.log',64,3)
  gc,forced=a.validate_retention_points(r)
  for p in r['post_stop_observation']:
   x=p['resources']['os_memory'];assert not x.get('error') and os.parse_rollup(x['smaps_rollup_raw'])==x['bytes']
  log=(dest/'go-tests.log').read_text();line=next(l for l in log.splitlines() if 'GO-SCAVENGE-CONTROL: ' in l);control=json.loads(line.split('GO-SCAVENGE-CONTROL: ',1)[1])
  assert control['gc_only']['heap_alloc']+24*1024*1024<=control['held']['heap_alloc'] and control['go_scavenged']['heap_released']>=control['held']['heap_released']+16*1024*1024
  for x in control.values():assert os.parse_rollup(x['os_memory']['smaps_rollup_raw'])==x['os_memory']['bytes']
  expected={m.point_key(p) for p in r['points'] if p['phase'] in ('warmup','measured')}|{m.point_key(p) for p in r['post_stop_observation']};actual={m.point_key(p) for p in c['samples']}
  missing=expected-actual;extra=actual-expected
  if missing or extra:
   assert tag=='initial' and mode=='ordinary' and missing=={m.point_key(gc[-1])} and not extra and not c['errors']
   # Verify every available raw map and frozen load hash; do not invent the
   # missing final pre-action map or call the diagnostic successful.
   for p in c['samples']:
    raw=folder/p['file'];assert hashlib.sha256(raw.read_bytes()).hexdigest()==p['sha256'];assert m.parse_smaps(gzip.open(raw,'rt').read(),c['race'])['groups']==p['groups']
    if p['phase'].startswith('poststop_'):assert p['load_evidence_sha256']==m.load_evidence_hash(r)
   result={'external_diagnostic':'failed_missing_pre_action_map','missing':sorted(missing),'extra':sorted(extra),'active_acceptance':s['status'],'active_error':error,'audited_events':events,'original_load':os.audit(folder/'pilot/native/report.json'),'post_stop_self_selected':[dict(phase=p['phase'],at_seconds=p['at_seconds'],**{k:p['resources'][k] for k in ('rss','heap_alloc','heap_released')}) for p in [gc[0],gc[-1]]+forced]}
  else:
   result=a.audit(folder);result['external_diagnostic']='complete'
   declared=json.loads((dest/'post-stop-audit.json').read_text())
   for key,value in declared.items():assert result[key]==value
  result['go_scavenge_calibration']=control
  out[mode]=result
  print(tag,mode,result['active_acceptance'],'activeRSS',round((result.get('active_rss_delta') or result['original_load']['statm_rss_delta'])/1048576,5),'events',events,'diag',result['external_diagnostic'])
  if result['external_diagnostic']=='complete':
   print(' post',[dict(phase=p['phase'],rss=round(p['statm_rss']/1048576,5),heapAlloc=round(p['heap_alloc']/1048576,5),heapReleased=round(p['heap_released']/1048576,5),shadow=round(p['groups_rss_bytes'].get('race_shadow',0)/1048576,5),unnamed=round(p['groups_rss_bytes'].get('unnamed_anonymous',0)/1048576,5)) for p in result['selected']])
 (base/f'{tag}-ci-audit.json').write_text(json.dumps(out,indent=2)+'\n')

if __name__=='__main__':audit_set(sys.argv[1],sys.argv[2])
