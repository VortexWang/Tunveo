from pathlib import Path
import json,sys,gzip
root=Path('/workspace/scratch/0db146b59a43/Tunveo');sys.path.insert(0,str(root/'scripts'));import soak_mappings as m
base=root/'artifacts/mapping-memory';out={}
for build in ('ordinary','race'):
 for trial in range(1,4):
  folder=base/'ci-unpacked'/f'soak-mappings-{build}'/f'trial-{trial}';a=m.audit(folder);r=json.loads((folder/'mapping-report.json').read_text());values=[]
  for at in (a['baseline_at_seconds'],a['peak_at_seconds']):
   point=next(s for s in r['samples'] if s['at_seconds']==at)
   maps=m.parse_smaps(gzip.open(folder/point['file'],'rt').read(),build=='race')['mappings'];v={}
   for item in maps:
    label=item['category']
    if label=='other_anonymous':label=item['path'] or 'unnamed_anonymous'
    v[label]=v.get(label,0)+item['bytes']['Rss']
   values.append(v)
  delta={k:values[1].get(k,0)-values[0].get(k,0) for k in sorted(values[0].keys()|values[1].keys())}
  assert sum(delta.values())==a['smaps_rss_delta']
  out[f'{build}-{trial}']={'baseline_at_seconds':a['baseline_at_seconds'],'peak_at_seconds':a['peak_at_seconds'],'rss_delta_bytes_by_vma_label':delta,'sum_matches_smaps_delta':True}
(base/'named-mapping-audit.json').write_text(json.dumps(out,indent=2)+'\n')
