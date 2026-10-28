#!/usr/bin/env python3
"""Extra full-smaps collection ABBA, process THP disabled in every sample."""
import argparse,hashlib,json,platform,subprocess,sys
from pathlib import Path

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('ordinary','race','launcher','artifacts'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--build',choices=['ordinary','race'],required=True);a=p.parse_args();a.artifacts.mkdir(parents=True,exist_ok=False)
 result={'status':'failed','qualifies_24h':False,'build':a.build,'kernel':platform.platform(),'order':['full','metadata_only','metadata_only','full'],'runs':[],'scope':'Only extra full smaps read/compress/hash differs; resource smaps_rollup, report serialization, GC/scavenge and logging remain. No allocation caller claims.'}
 policy_files=list(Path('/sys/kernel/mm/transparent_hugepage').glob('enabled'))+list(Path('/sys/kernel/mm/transparent_hugepage').glob('defrag'))+list(Path('/sys/kernel/mm/transparent_hugepage').glob('hugepages-*/enabled'))
 policy={str(p):p.read_text() for p in policy_files};result['host_thp_policy']=policy;info=None;binary=None
 for i,mode in enumerate(result['order'],1):
  folder=a.artifacts/f'{i}-{mode}';row={'index':i,'mapping_policy':mode,'errors':[]};result['runs'].append(row)
  command=[sys.executable,str(Path(__file__).with_name('soak_cycles.py')),'--ordinary',str(a.ordinary.resolve()),'--race',str(a.race.resolve()),'--launcher',str(a.launcher.resolve()),'--thp-control','process','--mapping-policy',mode,'--build',a.build,'--artifacts',str(folder)]
  row['host_thp_policy_before']={str(p):p.read_text() for p in policy_files};row['exit_code']=subprocess.call(command);row['host_thp_policy_after']={str(p):p.read_text() for p in policy_files}
  try:
   assert row['host_thp_policy_before']==policy==row['host_thp_policy_after']
   saved=json.loads((folder/'cycles.json').read_text());assert saved['mapping_policy']==mode and saved['thp_control']=='process' and not saved['qualifies_24h'] and len(saved['runs'])==1
   run=saved['runs'][0];row['resource_errors']=run['errors'];assert run['build']==a.build
   if info is not None:assert run['build_info']==info and run['binary_sha256']==binary
   info=run['build_info'];binary=run['binary_sha256'];assert run['exit_code']==0 and len(run['fixed_envelope']['cycles'])==3 and len(run['thp_observations'])>=204
   row['fixed_envelope']=run['fixed_envelope'];row['pid']=run['pid'];row['thp_observations']=run['thp_observations']
   if row['exit_code'] or run['errors']:row['errors'].append('resource/evidence failure retained')
  except (ValueError,KeyError,OSError,AssertionError) as e:row['errors'].append(type(e).__name__+': '+str(e))
  (a.artifacts/'snapshot-comparison.json').write_text(json.dumps(result,indent=2)+'\n')
 result['status']='diagnostic_passed' if all(not r['errors'] for r in result['runs']) else 'failed';result['build_info']=info;result['same_binary_sha256']=binary
 result['files']={str(p.relative_to(a.artifacts)):hashlib.sha256(p.read_bytes()).hexdigest() for p in a.artifacts.rglob('*') if p.is_file() and p.name!='snapshot-comparison.json'}
 (a.artifacts/'snapshot-comparison.json').write_text(json.dumps(result,indent=2)+'\n');return int(result['status']!='diagnostic_passed')
if __name__=='__main__':raise SystemExit(main())
