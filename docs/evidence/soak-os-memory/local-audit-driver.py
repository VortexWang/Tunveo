import hashlib,importlib.util,json,sys
from pathlib import Path
root=Path('/workspace/scratch/0db146b59a43/Tunveo')
sys.path.insert(0,str(root/'scripts'))
import verify_soak as v
import audit_soak_os_memory as os_audit
out=root/'artifacts/os-memory'
results={}
for build in ('ordinary','race'):
 for trial in range(1,4):
  d=out/f'{build}-{trial}';s=json.loads((d/'summary.json').read_text());r=json.loads((d/'native/report.json').read_text())
  for f,sha in s['files'].items():
   assert hashlib.sha256((d/f).read_bytes()).hexdigest()==sha,(d,f)
  assert s['exit_code']==0 and s['cleanup']['reaped'] and not s['cleanup']['forced_kill']
  assert not s['qualifies_24h'] and s['pilot']
  assert '54295c8f98177cebc18b61c4b1476526f6740474' in r['build_info'] and 'vcs.modified=false' in r['build_info']
  assert ('-race=true' in r['build_info'])==(build=='race')
  actual_error=None
  try: v.validate_report(r,True)
  except ValueError as e: actual_error=f'ValueError: {e}'
  assert (s['status']=='pilot_passed')==(actual_error is None)
  assert s.get('error')==actual_error
  events=v.validate_events(d/'native/exchanges.jsonl.gz',r)
  v.validate_engine_logs(d/'native',d/'stderr.log',64,3)
  results[f'{build}-{trial}']={'summary_status':s['status'],'error':actual_error,'audited_events':events,'counts':r['counts'],'warmup_counts':r['warmup_counts'],'file_hashes_verified':len(s['files']),'os_memory':os_audit.audit(d/'native/report.json')}
(out/'local-audit.json').write_text(json.dumps(results,indent=2)+'\n')
for name,a in results.items():
 m=a['os_memory'];print(name,a['summary_status'],'RSS',m['statm_rss_delta']/1048576,'Anonymous',m['rollup_delta_bytes']['Anonymous']/1048576,'heap',m['heap_alloc_delta']/1048576,'events',a['audited_events'])
