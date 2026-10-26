import hashlib,json,sys,zipfile
from pathlib import Path
root=Path('/workspace/scratch/0db146b59a43/Tunveo')
sys.path.insert(0,str(root/'scripts'))
import verify_soak as v
import audit_soak_os_memory as os_audit
out=root/'artifacts/os-memory';meta=json.loads((out/'ci-metadata.json').read_text());results={}
for a in meta['artifacts']['artifacts']:
 z=out/'ci-zips'/f"{a['name']}.zip"
 assert z.stat().st_size==a['size_in_bytes']
 assert 'sha256:'+hashlib.sha256(z.read_bytes()).hexdigest()==a['digest']
 dest=out/'ci-unpacked'/a['name'];dest.mkdir(parents=True,exist_ok=True)
 with zipfile.ZipFile(z) as f:
  assert f.testzip() is None
  assert all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in f.namelist())
  f.extractall(dest)
 if a['name']=='soak-timing-control':
  for name in ('parent','current'):
   p=json.loads((dest/f'checkpoint-{name}.json').read_text())
   results[f'timing-{name}']={'sha256':hashlib.sha256((dest/f'checkpoint-{name}.json').read_bytes()).hexdigest(),'result':p}
  continue
 build=a['name'].removeprefix('h2-rss-')
 declared_audit=json.loads((dest/'os-memory-audit.json').read_text())
 for trial in range(1,4):
  d=dest/f'trial-{trial}';s=json.loads((d/'summary.json').read_text());r=json.loads((d/'native/report.json').read_text())
  for f,sha in s['files'].items():assert hashlib.sha256((d/f).read_bytes()).hexdigest()==sha
  assert s['pilot'] and not s['qualifies_24h'] and s['exit_code']==0 and s['cleanup']['reaped'] and not s['cleanup']['forced_kill']
  assert meta['ci_checkout'] in r['build_info'] and 'vcs.modified=false' in r['build_info']
  assert ('-race=true' in r['build_info'])==(build=='race')
  assert s['binary_sha256']==(dest/'binary.sha256').read_text().split()[0]
  error=None
  try:v.validate_report(r,True)
  except ValueError as e:error=f'ValueError: {e}'
  assert (s['status']=='pilot_passed')==(error is None) and s.get('error')==error
  events=v.validate_events(d/'native/exchanges.jsonl.gz',r)
  v.validate_engine_logs(d/'native',d/'stderr.log',64,3)
  m=os_audit.audit(d/'native/report.json')
  assert m==declared_audit[f'artifacts/trial-{trial}/native/report.json']
  results[f'{build}-{trial}']={'summary_status':s['status'],'error':error,'audited_events':events,'counts':r['counts'],'file_hashes_verified':len(s['files']),'os_memory':m}
(out/'ci-audit.json').write_text(json.dumps(results,indent=2)+'\n')
for name,a in results.items():
 if 'os_memory' in a:
  m=a['os_memory'];print(name,a['summary_status'],'RSS',m['statm_rss_delta']/1048576,'Anon',m['rollup_delta_bytes']['Anonymous']/1048576,'Heap',m['heap_alloc_delta']/1048576,'events',a['audited_events'])
print('All artifact digest/CRC, source tree, per-file hashes, business/log/resource and raw OS audits verified')
