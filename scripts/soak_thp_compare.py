#!/usr/bin/env python3
"""Same-host ABBA diagnostic THP controls; failures remain failures."""
import argparse,hashlib,json,subprocess,sys,platform
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('ordinary','race','launcher','artifacts'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--build',choices=['ordinary','race'],required=True);p.add_argument('--control',choices=['go_heap','process'],required=True);a=p.parse_args()
    a.artifacts.mkdir(parents=True,exist_ok=False)
    result={'status':'failed','qualifies_24h':False,'build':a.build,'control':a.control,'order':['baseline',a.control,a.control,'baseline'],'runs':[],'scope':'Within-job ABBA same host; do not subtract different CI hosts or use intervention success to replace original gate.'}
    result['kernel']=platform.platform()
    policy_paths=list(Path('/sys/kernel/mm/transparent_hugepage').glob('enabled'))+list(Path('/sys/kernel/mm/transparent_hugepage').glob('defrag'))+list(Path('/sys/kernel/mm/transparent_hugepage').glob('hugepages-*/enabled'))
    policy={str(p):p.read_text() for p in policy_paths}
    result['host_thp_policy']=policy
    source=None;binary_hash=None
    for i,mode in enumerate(result['order'],1):
        folder=a.artifacts/f'{i}-{mode}';row={'index':i,'mode':mode,'errors':[]};result['runs'].append(row)
        command=[sys.executable,str(Path(__file__).with_name('soak_cycles.py')),'--ordinary',str(a.ordinary.resolve()),'--race',str(a.race.resolve()),'--launcher',str(a.launcher.resolve()),'--build',a.build,'--thp-control',mode,'--artifacts',str(folder)]
        row['host_thp_policy_before']={str(p):p.read_text() for p in policy_paths}
        row['exit_code']=subprocess.call(command)
        row['host_thp_policy_after']={str(p):p.read_text() for p in policy_paths}
        try:
            assert row['host_thp_policy_before']==policy==row['host_thp_policy_after'], 'host THP policy changed during diagnostic'
            saved=json.loads((folder/'cycles.json').read_text());assert not saved['qualifies_24h'] and len(saved['runs'])==1
            run=saved['runs'][0];assert run['build']==a.build and saved['thp_control']==mode
            if source is not None:assert run['build_info']==source and run['binary_sha256']==binary_hash
            source=run['build_info'];binary_hash=run['binary_sha256']
            row['resource_errors']=run['errors']
            assert run['exit_code']==0 and len(run['fixed_envelope']['cycles'])==3 and len(run['thp_observations'])>=204
            row['native_pid']=run['pid'];row['resource_errors']=run['errors'];row['fixed_envelope']=run['fixed_envelope'];row['thp_observations']=run['thp_observations']
            if row['exit_code'] or run['errors']:row['errors'].append('resource or evidence validation failed; original failure retained')
        except (ValueError,KeyError,OSError,AssertionError) as e:row['errors'].append(type(e).__name__+': '+str(e))
        (a.artifacts/'comparison.json').write_text(json.dumps(result,indent=2)+'\n')
    result['status']='diagnostic_passed' if all(not r['errors'] for r in result['runs']) else 'failed'
    result['same_binary_sha256']=binary_hash;result['build_info']=source
    result['files']={str(p.relative_to(a.artifacts)):hashlib.sha256(p.read_bytes()).hexdigest() for p in a.artifacts.rglob('*') if p.is_file() and p.name!='comparison.json'}
    (a.artifacts/'comparison.json').write_text(json.dumps(result,indent=2)+'\n')
    return int(result['status']!='diagnostic_passed')
if __name__=='__main__':raise SystemExit(main())
