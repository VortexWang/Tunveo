from pathlib import Path
import json,gzip,re,sys,hashlib
root=Path('/workspace/scratch/0db146b59a43/Tunveo');sys.path.insert(0,str(root/'scripts'));import soak_mappings as m
base=root/'artifacts/post-stop-retention';out={}
for tag in ('initial','ack'):
 for mode in ('ordinary','race'):
  folder=base/f'audit-{tag}-{mode}'/'window'
  if not folder.exists():continue
  report=json.loads((folder/'pilot/native/report.json').read_text());capture=json.loads((folder/'mapping-report.json').read_text());gc=[p for p in report['post_stop_observation'] if p['phase']=='poststop_gc'];force=[p for p in report['post_stop_observation'] if p['phase']=='poststop_go_scavenge'];rows=[]
  for point in report['post_stop_observation']:
   match=next((s for s in capture['samples'] if m.point_key(s)==m.point_key(point)),None)
   row={'phase':point['phase'],'at_seconds':point['at_seconds'],'native_rollup_anon_huge_pages':point['resources']['os_memory']['bytes']['AnonHugePages'],'external_map_available':match is not None}
   if match:
    p=folder/match['file'];assert hashlib.sha256(p.read_bytes()).hexdigest()==match['sha256'];raw=gzip.open(p,'rt').read();category=None;values={};vmas=[];current=None
    for line in raw.splitlines():
     header=m.HEADER.fullmatch(line)
     if header:
      current={'start':header[1],'end':header[2],'path':header[4]};vmas.append(current)
     elif current and re.match(r'^(AnonHugePages|LazyFree|Rss):',line):
      f=line.split();assert len(f)==3 and f[2]=='kB';current[f[0][:-1]]=int(f[1])*1024
    heap=[v for v in vmas if v['path']=='[anon: Go: heap]'];row.update(go_heap_vmas=heap,go_heap_rss=sum(v['Rss'] for v in heap),go_heap_anon_huge_pages=sum(v['AnonHugePages'] for v in heap),go_heap_lazy_free=sum(v['LazyFree'] for v in heap))
   rows.append(row)
  out[f'{tag}-{mode}']={'series':rows,'selected':[rows[0],rows[-2],rows[-1]],'scope':'raw VMA counts only, no hugepage policy change and no causal attribution; initial ordinary pre-action map remains unavailable'}
(base/'hugepage-observations.json').write_text(json.dumps(out,indent=2)+'\n')
for name,case in out.items():print(name,[(p['phase'],p.get('go_heap_rss',0)/1048576,p.get('go_heap_anon_huge_pages',0)/1048576,p.get('external_map_available')) for p in case['selected']])
