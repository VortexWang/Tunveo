import sys,time,json,hashlib
from pathlib import Path
root=Path('/workspace/scratch/0db146b59a43/Tunveo');sys.path.insert(0,str(root/'scripts'));import soak_mappings as m
base=root/'artifacts/post-stop-retention';seen={b:{} for b in ('ordinary','race')};done=set();deadline=time.monotonic()+450
while len(done)<2 and time.monotonic()<deadline:
 for b in ('ordinary','race'):
  if b in done:continue
  d=base/f'local-{b}'
  try:
   r=json.loads((d/'native/report.json').read_text());s=json.loads((d/'summary.json').read_text())
   if r.get('post_stop_observation'):
    p=r['post_stop_observation'][-1];key=(p['phase'],p['at_seconds'])
    if key not in seen[b]:
     seen[b][key]={'phase':key[0],'at_seconds':key[1],'load_evidence_sha256':m.load_evidence_hash(r),'point_sha256':hashlib.sha256(json.dumps(p,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
     (base/f'local-{b}-load-seals.json').write_text(json.dumps(list(seen[b].values()),indent=2)+'\n')
   if s['status']!='running':done.add(b)
  except (FileNotFoundError,json.JSONDecodeError):pass
 time.sleep(.01)
print('local JSON-only load seals', {b:len(v) for b,v in seen.items()},'done',sorted(done),flush=True)
