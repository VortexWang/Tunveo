from pathlib import Path
import sys,json,zipfile,hashlib,gzip,statistics
root=Path('/workspace/scratch/0db146b59a43/Tunveo');sys.path.insert(0,str(root/'scripts'));import soak_mappings as m;import audit_soak_allocations as alloc
base=root/'artifacts/allocator-memory'

def audit_set(metadata_file,tag):
 meta=json.loads((base/metadata_file).read_text());out={}
 for item in meta['artifacts']['artifacts']:
  build='race' if item['name'].endswith('-race') else 'ordinary';z=base/'ci-zips'/f'soak-allocations-{build}-{tag}.zip'
  assert z.stat().st_size==item['size_in_bytes'] and 'sha256:'+hashlib.sha256(z.read_bytes()).hexdigest()==item['digest']
  dest=base/f'{build}-{tag}'
  with zipfile.ZipFile(z) as f:
   assert f.testzip() is None and all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in f.namelist());f.extractall(dest)
  c=json.loads((dest/'control/control.json').read_text());race=build=='race';assert c['race']==race and c['exit_code']==0
  assert c['shadow_rss_delta'] >=48*1024*1024 if race else c['shadow_rss_delta']==0
  assert c['predicted_shadow_mapping_observed']==race
  assert '5bdd6b292a1d7bb4a21c3134bafec7545f23133e2e640fed265a7f8c5b67a638' in (dest/'binary-sha256.txt').read_text()
  for row in c['rows']:
   assert meta['checkout'] in row['stage']['build_info'] and 'vcs.modified=false' in row['stage']['build_info']
   p=dest/'control'/row['snapshot']['file'];assert hashlib.sha256(p.read_bytes()).hexdigest()==row['snapshot']['sha256']
   assert m.parse_smaps(gzip.open(p,'rt').read(),race)['groups']==row['snapshot']['groups']
  target=c['rows'][1]['stage']['address']*2+m.RANGES['race_shadow'][0]
  assert target==c['expected_shadow_address'] and c['rows'][1]['stage']['size']==32*1024*1024
  touched=m.parse_smaps(gzip.open(dest/'control'/c['rows'][1]['snapshot']['file'],'rt').read(),race)['mappings']
  assert any(v['start']<=target<v['end'] and v['category']=='race_shadow' and v['bytes']['Rss']>0 for v in touched)==race
  control_audit=alloc.audit(dest/'control',dest/'control.trace',True)
  if (dest/'control-allocations.json').exists():assert control_audit==json.loads((dest/'control-allocations.json').read_text())
  windows={}
  for name in ('traced','untraced-180'):
   folder=dest/name
   if not folder.exists():windows[name]={'status':'not_run','reason':'initial CI audit-parser failure prevented load step'};continue
   capture=json.loads((folder/'mapping-report.json').read_text());assert meta['checkout'] in capture['description']['build_info']
   assert capture['binary_sha256']==(dest/'binary-sha256.txt').read_text().splitlines()[0].split()[0]
   mapping=m.audit(folder)
   assert mapping==json.loads((folder/'mapping-audit.json').read_text())
   report=json.loads((folder/'pilot/native/report.json').read_text());s=report['settings'];measured=[p for p in report['points'] if p['phase']=='measured']
   first=[p for p in measured if p['at_seconds']<=s['warmup_seconds']+30];last=[p for p in measured if p['at_seconds']>=s['warmup_seconds']+s['duration_seconds']-30]
   curve={key:{'early_median':statistics.median(p['resources'][key] for p in first),'late_median':statistics.median(p['resources'][key] for p in last),'early_to_late_delta':statistics.median(p['resources'][key] for p in last)-statistics.median(p['resources'][key] for p in first)} for key in ('rss','heap_alloc','heap_sys')}
   result={'mapping_audit':mapping,'duration_seconds':s['duration_seconds'],'counts':report['counts'],'curve':curve}
   if name=='traced':
    attribution=alloc.audit(folder,dest/'pilot.trace')
    if (dest/'pilot-allocations.json').exists():assert attribution==json.loads((dest/'pilot-allocations.json').read_text())
    result['allocations']=attribution
    b=next(row for row in attribution['rows'] if row['at_seconds']==mapping['baseline_at_seconds']);p=next(row for row in attribution['rows'] if row['at_seconds']==mapping['peak_at_seconds']);delta={k:p['groups'].get(k,0)-b['groups'].get(k,0) for k in sorted(b['groups'].keys()|p['groups'].keys())};assert sum(delta.values())==mapping['smaps_rss_delta'];result['allocation_delta_bytes']=delta
   windows[name]=result
   print(tag,build,name,mapping['status'],'RSS',round(mapping['statm_rss_delta']/1048576,5),'early-lateRSS',round(curve['rss']['early_to_late_delta']/1048576,5),'events',mapping['audited_events'])
   if name=='traced':print(' allocation deltasMiB',{k:round(v/1048576,6) for k,v in delta.items() if v})
  out[build]={'control':control_audit,'control_shadow_rss_delta':c['shadow_rss_delta'],'windows':windows}
 (base/f'{tag}-ci-audit.json').write_text(json.dumps(out,indent=2)+'\n')

if __name__=='__main__':audit_set(sys.argv[1],sys.argv[2])
