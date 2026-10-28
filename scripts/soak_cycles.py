#!/usr/bin/env python3
"""Three cycles per process, fixed first warmup envelope, diagnostic only."""
import argparse,gzip,hashlib,json,subprocess,sys,os,re
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


def control_environment(mode, inherited):
    env=dict(inherited)
    if env.get('GODEBUG') or env.get('GORACE'):raise ValueError('THP controls require empty inherited GODEBUG/GORACE')
    if mode=='go_heap':env['GODEBUG']='disablethp=1'
    elif mode not in ('baseline','process'):raise ValueError('unknown THP control')
    return env


def thp_observation(raw, record, mode):
    expected_env='disablethp=1' if mode=='go_heap' else ''
    if record.get('godebug')!=expected_env or record.get('thp_enabled')!=('0' if mode=='process' else '1'):
        raise ValueError('actual target THP/environment control not effective')
    heap=False;total=0;go_heap=0
    for line in raw.splitlines():
        if re.match(r'^[0-9a-f]+-[0-9a-f]+ ',line):heap=line.endswith('[anon: Go: heap]')
        m=re.fullmatch(r'AnonHugePages:\s+(\d+) kB',line)
        if m:
            value=int(m[1])*1024;total+=value
            if heap:go_heap+=value
    if mode=='process' and total:raise ValueError('process-disabled target still has AnonHugePages')
    if mode=='go_heap' and go_heap:raise ValueError('Go heap control still has named-heap AnonHugePages')
    return {'anon_huge_bytes':total,'go_named_heap_huge_bytes':go_heap}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('ordinary','race','artifacts'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--thp-control',choices=['baseline','go_heap','process'])
    p.add_argument('--launcher',type=Path)
    p.add_argument('--mapping-policy',choices=['full','metadata_only'],default='full')
    p.add_argument('--build',choices=['all','ordinary','race'],default='all')
    a=p.parse_args()
    if a.thp_control and not a.launcher:p.error('THP controls require launcher')
    if a.mapping_policy=='metadata_only' and a.thp_control!='process':p.error('metadata-only requires verified process THP control')
    a.artifacts.mkdir(parents=True,exist_ok=False)
    result={'status':'failed','qualifies_24h':False,'thp_control':a.thp_control,'mapping_policy':a.mapping_policy,'runs':[]};revision=None
    for name in (('ordinary','race') if a.build=='all' else (a.build,)):
        folder=a.artifacts/name;binary=getattr(a,name).resolve();row={'build':name,'errors':[]};result['runs'].append(row)
        try:
            info=json.loads(subprocess.check_output([str(binary),'--describe'],timeout=10))['build_info']
            assert 'vcs.modified=false' in info and ('-race=true' in info)==(name=='race')
            rev=next(x for x in info.splitlines() if x.startswith('build\tvcs.revision='))
            if revision is not None:assert rev==revision
            revision=rev;row['build_info']=info;row['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
            command=[str(binary),'--diagnostic-cycles','3','--transport','3','--mode','1','--duration','180s','--warmup','12s','--sample-interval','5s','--workers','2','--qps','10','--pool-min','16','--pool-max','64','--post-stop-observe','120s','--diagnostic-go-scavenge','--artifacts',str(folder)]
            if a.mapping_policy=='metadata_only':command.append('--diagnostic-mapping-metadata-only')
            env=None
            if a.thp_control:
                env=control_environment(a.thp_control,os.environ)
                evidence=a.artifacts/(name+'-control.json')
                command=[str(a.launcher.resolve()),'disable' if a.thp_control=='process' else 'keep',str(evidence)]+command
            row['command']=command
            with (a.artifacts/(name+'-stdout.log')).open('w') as out,(a.artifacts/(name+'-stderr.log')).open('w') as err:
                proc=subprocess.Popen(command,stdout=out,stderr=err,env=env);row['pid']=proc.pid
                try:row['exit_code']=proc.wait(timeout=3*432)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:proc.wait(timeout=30)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
                    raise ValueError('native repeated run timed out')
            assert row['exit_code']==0
            if a.thp_control:
                control=json.loads(evidence.read_text());assert control=={'pid':row['pid'],'before':0,'after':int(a.thp_control=='process')}
                row['launcher_control']=control;row['thp_observations']=[]
            reports=[];previous_mapping_end=-1
            for i in range(1,4):
                cycle=folder/f'cycle-{i}';r=json.loads((cycle/'report.json').read_text());reports.append(r)
                assert r['build_info']==info and r['settings']['pid']==row['pid']
                s=r['settings'];assert s.get('diagnostic_mapping_policy')==a.mapping_policy
                if a.thp_control=='process':
                    for point in r['points']+r['post_stop_observation']:
                        assert point['resources']['os_memory']['bytes']['AnonHugePages']==0
                assert (r['transport'],r['mode'],s['tls'],s['duration_seconds'],s['warmup_seconds'],s['sample_interval_seconds'],s['workers'],s['qps'],s['pool_min'],s['pool_max'])==(3,1,1,180,12,5,2,10,16,64)
                for label,fn in [('report',lambda:v.validate_report(r,True)),('events',lambda:v.validate_events(cycle/'exchanges.jsonl.gz',r)),('logs',lambda:v.validate_engine_logs(cycle,a.artifacts/(name+'-stderr.log'),64,3))]:
                    try:fn()
                    except (ValueError,KeyError,OSError,EOFError) as e:row['errors'].append(f'cycle-{i} {label}: {e}')
                records=[json.loads(x) for x in (cycle/'mapping-index.jsonl').read_text().splitlines()]
                assert len(records)>=68
                for record in records:
                    assert record['pid']==row['pid'] and record['cycle']==i and previous_mapping_end<=record['read_start_monotonic_ns']<=record['read_end_monotonic_ns']
                    previous_mapping_end=record['read_end_monotonic_ns']
                    assert record['mapping_policy']==a.mapping_policy
                    if a.mapping_policy=='full':
                        raw=gzip.decompress((cycle/record['file']).read_bytes())
                        assert hashlib.sha256(raw).hexdigest()==record['sha256_raw']
                        if a.thp_control:row['thp_observations'].append(dict(cycle=i,**thp_observation(raw.decode(),record,a.thp_control)))
                    else:
                        assert 'file' not in record and 'sha256_raw' not in record
                        assert not list(cycle.glob('mapping-*.smaps.gz'))
                        assert record['thp_enabled']=='0' and record['godebug']==''
                        row['thp_observations'].append({'cycle':i,'anon_huge_bytes':None,'go_named_heap_huge_bytes':None,'scope':'metadata only; THP checked by target status and existing resource rollup, no full VMA sample'})
            row['fixed_envelope']=fixed_envelope(reports)
            if not row['fixed_envelope']['passed']:row['errors'].append('original first-cycle fixed active envelope exceeded')
        except (ValueError,KeyError,OSError,AssertionError,StopIteration,subprocess.SubprocessError) as e:row['errors'].append(type(e).__name__+': '+str(e))
        (a.artifacts/'cycles.json').write_text(json.dumps(result,indent=2)+'\n')
    result['status']='diagnostic_passed' if all(not r['errors'] for r in result['runs']) else 'failed'
    result['files']={str(p.relative_to(a.artifacts)):hashlib.sha256(p.read_bytes()).hexdigest() for p in a.artifacts.rglob('*') if p.is_file() and p.name!='cycles.json'}
    (a.artifacts/'cycles.json').write_text(json.dumps(result,indent=2)+'\n')
    return int(result['status']!='diagnostic_passed')
if __name__=='__main__':raise SystemExit(main())
