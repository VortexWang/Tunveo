#!/usr/bin/env python3
"""Sequential ordinary/race pilot comparison; never grants 24h qualification."""
import argparse
import hashlib
import json
import statistics
import subprocess
import sys
from pathlib import Path
import verify_soak as v


def resources(report):
    points=report['points'];s=report['settings']
    warm=[p for p in points if p['phase']=='warmup' and p['at_seconds']>=s['warmup_seconds']/2]
    steady=[p for p in points if p['phase']=='measured']
    if len(warm)<3 or len(steady)<3:raise ValueError('insufficient resource samples')
    out={'active':{},'return':{},'trend':{},'qualifies_24h':False,'warmup_rss':[{'at_seconds':p['at_seconds'],'rss':p['resources']['rss']} for p in warm]}
    for key,limit in v.ACTIVE.items():
        base=max(p['resources'][key] for p in warm);peak=max(p['resources'][key] for p in steady)
        bad=[{'at_seconds':p['at_seconds'],'value':p['resources'][key]} for p in steady if not 0<p['resources'][key]<=base+limit]
        out['active'][key]={'baseline':base,'peak':peak,'delta':peak-base,'allowance':limit,'passed':not bad,'violations':bad}
    for key,limit in v.RETURN.items():
        base=report['idle_baseline'][key];after=report['after_stop'][key]
        out['return'][key]={'baseline':base,'after_stop':after,'allowance':limit,'passed':0<after<=base+limit}
    q=max(1,len(steady)//4)
    for key,limit in v.TREND.items():
        delta=statistics.median(p['resources'][key] for p in steady[-q:])-statistics.median(p['resources'][key] for p in steady[:q])
        out['trend'][key]={'delta':delta,'formal_allowance':limit,'enforced_in_pilot':False}
    return out


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ordinary',type=Path,required=True);p.add_argument('--race',type=Path,required=True);p.add_argument('--artifacts',type=Path,required=True);a=p.parse_args()
    a.artifacts.mkdir(parents=True,exist_ok=False)
    result={'status':'failed','qualifies_24h':False,'order':['ordinary','race','race','ordinary'],'runs':[],'scope':'Same host sequential ABBA fresh processes; no BPF or observer ACK. Native 180s load +12s warmup +120s post-stop GC/scavenge. Not a causal comparison with instrumented PR31.'}
    meta={}
    try:
        for name in ['ordinary','race']:
            binary=getattr(a,name).resolve();d=json.loads(subprocess.check_output([str(binary),'--describe'],timeout=10))
            info=d['build_info'];assert ('-race=true' in info)==(name=='race');assert 'vcs.modified=false' in info, 'dirty or missing VCS build provenance'
            rev=next(x for x in info.splitlines() if x.startswith('build\tvcs.revision='));meta[name]=(binary,rev)
        assert meta['ordinary'][1]==meta['race'][1]
    except (ValueError,KeyError,OSError,AssertionError,StopIteration,subprocess.SubprocessError) as error:
        result['preflight_error']=type(error).__name__+': '+str(error)
        (a.artifacts/'pair.json').write_text(json.dumps(result,indent=2)+'\n')
        return 1
    result['source_revision']=meta['ordinary'][1]
    for i,name in enumerate(result['order']):
        folder=a.artifacts/f'{i+1}-{name}';binary=meta[name][0]
        command=[sys.executable,str(Path(v.__file__).resolve()),'--binary',str(binary),'--transport','3','--mode','1','--pilot','--duration-seconds','180','--warmup-seconds','12','--sample-seconds','5','--pool-min','16','--pool-max','64','--workers','2','--qps','10','--post-stop-observe-seconds','120','--diagnostic-go-scavenge','--artifacts',str(folder)]
        code=subprocess.call(command)
        row={'build':name,'exit_code':code,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'errors':[]}
        try:
            summary=json.loads((folder/'summary.json').read_text());r=json.loads((folder/'native/report.json').read_text())
            assert r['build_info']==json.loads(subprocess.check_output([str(binary),'--describe'],timeout=10))['build_info']
            row['original_summary']=summary;row['resources']=resources(r)
            for label,check in [('report',lambda:v.validate_report(r,True)),('events',lambda:v.validate_events(folder/'native/exchanges.jsonl.gz',r)),('logs',lambda:v.validate_engine_logs(folder/'native',folder/'stderr.log',64,3))]:
                try:row[label]=check()
                except (ValueError,KeyError,OSError,EOFError) as e:row['errors'].append(label+': '+str(e))
        except (ValueError,KeyError,OSError,AssertionError,subprocess.SubprocessError) as e:row['errors'].append(type(e).__name__+': '+str(e))
        result['runs'].append(row)
        (a.artifacts/'pair.json').write_text(json.dumps(result,indent=2)+'\n')
    result['status']='pilot_passed' if all(x['exit_code']==0 and not x['errors'] for x in result['runs']) else 'failed'
    (a.artifacts/'pair.json').write_text(json.dumps(result,indent=2)+'\n')
    return int(result['status']!='pilot_passed')

if __name__=='__main__':raise SystemExit(main())
