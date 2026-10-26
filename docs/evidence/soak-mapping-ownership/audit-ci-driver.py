from pathlib import Path
import sys,json,gzip,hashlib,zipfile
root=Path('/workspace/scratch/0db146b59a43/Tunveo');sys.path.insert(0,str(root/'scripts'));import soak_mappings as m
base=root/'artifacts/mapping-memory';meta=json.loads((base/'ci-metadata.json').read_text());results={}
for artifact in meta['artifacts']['artifacts']:
 name=artifact['name'];z=base/'ci-zips'/f'{name}.zip'
 assert z.stat().st_size==artifact['size_in_bytes']
 assert 'sha256:'+hashlib.sha256(z.read_bytes()).hexdigest()==artifact['digest']
 dest=base/'ci-unpacked'/name;dest.mkdir(parents=True,exist_ok=True)
 with zipfile.ZipFile(z) as f:
  assert f.testzip() is None
  assert all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in f.namelist())
  f.extractall(dest)
 race=name.endswith('-race');control=json.loads((dest/'control/control.json').read_text())
 assert control['race']==race and control['exit_code']==0
 assert '5bdd6b292a1d7bb4a21c3134bafec7545f23133e2e640fed265a7f8c5b67a638' in (dest/'binary-sha256.txt').read_text()
 parsed=[]
 for row in control['rows']:
  path=dest/'control'/row['snapshot']['file']
  assert hashlib.sha256(path.read_bytes()).hexdigest()==row['snapshot']['sha256']
  p=m.parse_smaps(gzip.open(path,'rt').read(),race);assert p['groups']==row['snapshot']['groups'];parsed.append(p)
  assert meta['ci_checkout'] in row['stage']['build_info'] and 'vcs.modified=false' in row['stage']['build_info']
 shadow_delta=parsed[1]['groups'].get('race_shadow',{}).get('Rss',0)-parsed[0]['groups'].get('race_shadow',{}).get('Rss',0)
 assert shadow_delta==control['shadow_rss_delta'] and (shadow_delta>=48*1024*1024 if race else shadow_delta==0)
 predicted=control['rows'][1]['stage']['address']*2+m.RANGES['race_shadow'][0]
 assert predicted==control['expected_shadow_address']
 assert control['rows'][1]['stage']['size']==32*1024*1024
 observed=any(v['start']<=predicted<v['end'] and v['category']=='race_shadow' and v['bytes']['Rss']>0 for v in parsed[1]['mappings'])
 assert observed==control['predicted_shadow_mapping_observed'] and (observed if race else not observed)
 results[name]={'control_shadow_delta':shadow_delta,'control_prediction_observed':observed,'pilots':{}}
 for trial in range(1,4):
  folder=dest/f'trial-{trial}';audit=m.audit(folder)
  assert audit==json.loads((folder/'mapping-audit.json').read_text())
  capture=json.loads((folder/'mapping-report.json').read_text())
  assert meta['ci_checkout'] in capture['description']['build_info']
  results[name]['pilots'][str(trial)]=audit
  delta=audit['groups_delta_bytes'];print(name,trial,'statmRSS',audit['statm_rss_delta']/1048576,'smapsRSS',audit['smaps_rss_delta']/1048576,'groupsRSS',{k:v['Rss']/1048576 for k,v in delta.items()},'lag',audit['selected_checkpoint_age_seconds'])
 print(name,'32MiB control shadow delta',shadow_delta/1048576,'MiB')
(base/'ci-audit.json').write_text(json.dumps(results,indent=2)+'\n')
print('All artifact CRC/digests, control predictions, mapping/checkpoint/hash/source/business/log/resource audits verified')
