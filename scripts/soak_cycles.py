#!/usr/bin/env python3
"""Three cycles per process, fixed first warmup envelope, diagnostic only."""
import argparse,gzip,hashlib,json,subprocess,sys
from pathlib import Path
import verify_soak as v
import soak_build_pair as pair


def fixed_envelope(reports):
    if len(reports)!=3:raise ValueError('three complete cycles required')
    pids={r['settings']['pid'] for r in reports}
    if len(pids)!=1:raise ValueError('cycles must share one PID')
    first=reports[0];warm=[p for p in first['points'] if p['phase']=='warmup' and p['at_seconds']>=first['settings']['warmup_seconds']/2]
    if len(warm)<3:raise ValueError('insufficient first warmup')
    baseline={k:max(p['resources'][k] for p in warm) for k in v.ACTIVE}
    rows=[]
    for i,r in enumerate(reports,1):
        if (r['settings'].get('diagnostic_cycles'),r['settings'].get('diagnostic_cycle_index'))!=(3,i):raise ValueError('cycle identity mismatch')
        measured=[p for p in r['points'] if p['phase']=='measured']
        if len(measured)<3:raise ValueError('missing measured window')
        checks={k:{'baseline':baseline[k],'peak':max(p['resources'][k] for p in measured),'allowance':limit,'violations':[{'at_seconds':p['at_seconds'],'value':p['resources'][k]} for p in measured if not 0<p['resources'][k]<=baseline[k]+limit]} for k,limit in v.ACTIVE.items()}
        post=r['post_stop_observation']
        if len(post)<26 or post[-1]['phase']!='poststop_go_scavenge':raise ValueError('incomplete stop/scavenge observation')
        gc=[p for p in post if p['phase']=='poststop_gc']
        rows.append({'cycle':i,'checks':checks,'first_gc_rss':gc[0]['resources']['rss'],'last_gc_rss':gc[-1]['resources']['rss'],'minimum_gc_rss':min(p['resources']['rss'] for p in gc),'go_scavenge_rss':post[-1]['resources']['rss'],'local_resources':pair.resources(r)})
    return {'pid':next(iter(pids)),'baseline':baseline,'cycles':rows,'passed':all(not c['violations'] for row in rows for c in row['checks'].values()),'qualifies_24h':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('ordinary','race','artifacts'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();a.artifacts.mkdir(parents=True,exist_ok=False)
    result={'status':'failed','qualifies_24h':False,'runs':[]};revision=None
    for name in ('ordinary','race'):
        folder=a.artifacts/name;binary=getattr(a,name).resolve();row={'build':name,'errors':[]};result['runs'].append(row)
        try:
            info=json.loads(subprocess.check_output([str(binary),'--describe'],timeout=10))['build_info']
            assert 'vcs.modified=false' in info and ('-race=true' in info)==(name=='race')
            rev=next(x for x in info.splitlines() if x.startswith('build\tvcs.revision='))
            if revision is not None:assert rev==revision
            revision=rev;row['build_info']=info;row['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
            command=[str(binary),'--diagnostic-cycles','3','--transport','3','--mode','1','--duration','180s','--warmup','12s','--sample-interval','5s','--workers','2','--qps','10','--pool-min','16','--pool-max','64','--post-stop-observe','120s','--diagnostic-go-scavenge','--artifacts',str(folder)]
            with (a.artifacts/(name+'-stdout.log')).open('w') as out,(a.artifacts/(name+'-stderr.log')).open('w') as err:
                proc=subprocess.Popen(command,stdout=out,stderr=err);row['pid']=proc.pid
                try:row['exit_code']=proc.wait(timeout=3*432)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:proc.wait(timeout=30)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
                    raise ValueError('native repeated run timed out')
            assert row['exit_code']==0
            reports=[];previous_mapping_end=-1
            for i in range(1,4):
                cycle=folder/f'cycle-{i}';r=json.loads((cycle/'report.json').read_text());reports.append(r)
                assert r['build_info']==info and r['settings']['pid']==row['pid']
                s=r['settings'];assert (r['transport'],r['mode'],s['tls'],s['duration_seconds'],s['warmup_seconds'],s['sample_interval_seconds'],s['workers'],s['qps'],s['pool_min'],s['pool_max'])==(3,1,1,180,12,5,2,10,16,64)
                for label,fn in [('report',lambda:v.validate_report(r,True)),('events',lambda:v.validate_events(cycle/'exchanges.jsonl.gz',r)),('logs',lambda:v.validate_engine_logs(cycle,a.artifacts/(name+'-stderr.log'),64,3))]:
                    try:fn()
                    except (ValueError,KeyError,OSError,EOFError) as e:row['errors'].append(f'cycle-{i} {label}: {e}')
                records=[json.loads(x) for x in (cycle/'mapping-index.jsonl').read_text().splitlines()]
                assert len(records)>=68
                for record in records:
                    assert record['pid']==row['pid'] and record['cycle']==i and previous_mapping_end<=record['read_start_monotonic_ns']<=record['read_end_monotonic_ns']
                    previous_mapping_end=record['read_end_monotonic_ns']
                    assert hashlib.sha256(gzip.decompress((cycle/record['file']).read_bytes())).hexdigest()==record['sha256_raw']
            row['fixed_envelope']=fixed_envelope(reports)
            if not row['fixed_envelope']['passed']:row['errors'].append('original first-cycle fixed active envelope exceeded')
        except (ValueError,KeyError,OSError,AssertionError,StopIteration,subprocess.SubprocessError) as e:row['errors'].append(type(e).__name__+': '+str(e))
        (a.artifacts/'cycles.json').write_text(json.dumps(result,indent=2)+'\n')
    result['status']='diagnostic_passed' if all(not r['errors'] for r in result['runs']) else 'failed'
    result['files']={str(p.relative_to(a.artifacts)):hashlib.sha256(p.read_bytes()).hexdigest() for p in a.artifacts.rglob('*') if p.is_file() and p.name!='cycles.json'}
    (a.artifacts/'cycles.json').write_text(json.dumps(result,indent=2)+'\n')
    return int(result['status']!='diagnostic_passed')
if __name__=='__main__':raise SystemExit(main())
