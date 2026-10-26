import subprocess,json,hashlib,concurrent.futures,datetime
from pathlib import Path
root=Path('/workspace/scratch/0db146b59a43/Tunveo');out=root/'artifacts/post-stop-retention';record={'source':'0d2b8eb2e7542e7f4406f72687afc8403b466db2','source_tree':'f3ff7bb5dd7108c277c57ac01944d7fa9d3052de','scope':'same-host concurrent ordinary/race total20QPS,180s measured then120s post-stop GC-sampled observation and explicit Go-scavenge; no strace or external proc reads; background metadata review during run','builds':{},'runs':[]}
for mode in ('ordinary','race'):
 binary=root/f'bin/retention-{mode}';desc=json.loads(subprocess.check_output([str(binary),'--describe']));assert record['source'] in desc['build_info'] and 'vcs.modified=false' in desc['build_info'];record['builds'][mode]={'description':desc,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
def run(mode):
 cmd=['python3','scripts/verify_soak.py','--binary',f'bin/retention-{mode}','--transport','3','--mode','1','--pilot','--duration-seconds','180','--warmup-seconds','12','--sample-seconds','5','--workers','2','--qps','10','--pool-min','16','--pool-max','64','--post-stop-observe-seconds','120','--diagnostic-go-scavenge','--artifacts',f'artifacts/post-stop-retention/local-{mode}']
 start=datetime.datetime.now(datetime.timezone.utc).isoformat()
 with (out/f'local-{mode}-driver.log').open('w') as f:rc=subprocess.run(cmd,cwd=root,stdout=f,stderr=subprocess.STDOUT).returncode
 return dict(build=mode,command=cmd,started_at=start,finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),exit_code=rc)
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as e:
 tasks=[e.submit(run,b) for b in ('ordinary','race')]
 for f in concurrent.futures.as_completed(tasks):
  result=f.result();record['runs'].append(result);print(json.dumps(result),flush=True)
  (out/'local-execution.json').write_text(json.dumps(record,indent=2)+'\n')
