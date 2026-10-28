"""Offline source-pinned replay; archived target/tracer are never executed."""
import argparse,hashlib,json,sys,tempfile,zipfile
from collections import Counter
from pathlib import Path
from unittest.mock import patch
PINS={"audit_soak_os_memory.py":"0c5fbff721f98f94fb75f431da968679908d1171","audit_soak_retention.py":"3b06a71491258e62326f4d3d7f4dc4bdae10ca0b","soak_call_lifecycle.py":"0847600f9edce17e44de47e384a0992d54167828","soak_callsite_control.py":"ab76a87a1ebe6281b0372c6614f6a70aad8f7660","soak_mapping_ledger.py":"610a54d636767bf92752bd165b60faafd961c7be","soak_mapping_retention.py":"ae88355fbc1363aa3f60c45cb9e773544a07bf70","soak_mappings.py":"708301538c24476e4d244efb16cc5027c193efd5","soak_ret_context.py":"eac5605150e51b9aec336277088e3981616ac28e","verify_soak.py":"e0c0321054c8be6510f190b33d07966aad8635aa"}
def sha(b):return hashlib.sha256(b).hexdigest()
def safe(n):return not Path(n).is_absolute() and '..' not in Path(n).parts
def canon(x):return json.loads(json.dumps(x))
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for n in ('archive','scripts-dir','output'):ap.add_argument('--'+n,type=Path,required=True)
    ap.add_argument('--sha256',required=True);ap.add_argument('--source',required=True);ap.add_argument('--aligned-blob',required=True);args=ap.parse_args()
    pins=dict(PINS,**{'soak_aligned_calls.py':args.aligned_blob})
    assert sha(args.archive.read_bytes())==args.sha256
    for n,h in pins.items():
        b=(args.scripts_dir/n).read_bytes();assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==h,n
    sys.path.insert(0,str(args.scripts_dir.resolve()));import soak_aligned_calls as a
    result=dict(audit_status='independently_replayed',execution_source=args.source,source_blobs=pins,archive_sha256=args.sha256,qualifies_24h=False,stages=[])
    with tempfile.TemporaryDirectory() as t:
        root=Path(t)
        with zipfile.ZipFile(args.archive) as z:
            assert z.testzip() is None and len(z.namelist())==len(set(z.namelist())) and all(safe(n) for n in z.namelist());z.extractall(root)
        exp=root/'experiment';saved=json.loads((exp/'experiment.json').read_text());assert saved['rss_budget']==a.verify.ACTIVE['rss']==67108864 and not saved['qualifies_24h'] and saved['historical_failures_retained']
        result['original_status']=saved['status'];result['original_error']=saved.get('error')
        for n,h in saved['files'].items():assert safe(n) and sha((exp/n).read_bytes())==h,n
        for line in (root/'binary-sha256.txt').read_text().splitlines():
            h,n=line.split();assert sha((root/Path(n).relative_to('artifacts')).read_bytes())==h
        a.direct.extract(root/'original-race.zip',root/'recovered-probe');assert (root/'recovered-probe').read_bytes()==(root/'binaries/probe').read_bytes()
        assert sha((root/'binaries/tracer').read_bytes())=='fbe7876f21ca1bc80dd688bbb143dd14f7dfa95d2ba63a819bd5b844eaeda9c9'
        info=(root/'bpftrace-info.txt').read_text();assert 'bfd: yes' in info and 'unsafe probe: no' in info
        assert 'not found' not in (root/'tracer-ldd.txt').read_text()
        prov=json.loads((root/'tracer-provenance.json').read_text());assert prov['archive_sha256']=='616f8c4da929312196c654dda4c28dac997ba12c1eafdd4b8caa32f920bc7850' and prov['artifact']==12813365084
        totals=Counter()
        for name in ('control','15s','180s'):
            folder=exp/name
            if not folder.exists():result['stages'].append(dict(stage=name,status='not_started'));continue
            binary=root/'binaries'/('control' if name=='control' else 'probe');plan=json.loads((folder/'plan.json').read_text());run=json.loads((folder/'execution.json').read_text())
            assert sha(binary.read_bytes())==plan['binary_sha256'] and run['exit_code']==0 and not run['timed_out'] and run['group_gone'] and not run['cleanup_signals'] and run['target_identity_verified']
            for k,n in [('target_identity','target-before.stat'),('tracer_identity','tracer-before.stat')]:assert a.context.proc_identity((folder/n).read_text())==run[k]
            assert a.context.owned_groups(run['process_group'],run['target_identity'],run['tracer_identity'],(folder/'tracer-exe.txt').read_text(),Path(run['command'][2]))==run['owned_groups']
            assert not (folder/'bpftrace-stderr.log').read_text()
            local=a.context.plan(binary,{int(k):f['symbol'] for k,f in plan['functions'].items()})
            def norm(f):
                q=dict(f);s=q['disassembly'];q['disassembly']=s[s.index('Disassembly of section'):];return q
            assert {k:norm(f) for k,f in plan['functions'].items()}=={k:norm(f) for k,f in local['functions'].items()}
            site=a.direct.call_site(local);layout=a.qualify(local)
            # Only path-dependent instruction resolvers are substituted, after
            # independent ELF/full-disassembly validation. Raw plan/exec/events stay original.
            with patch.object(a.direct,'call_site',return_value=site),patch.object(a,'qualify',return_value=layout):
                assert a.program(plan)==(folder/'program.bt').read_text()
                try:parsed=canon(a.audit((folder/'events.log').read_text(),plan,run['expected_uid']))
                except ValueError as error:
                    assert name=='control' and saved['error']=='ValueError: '+str(error) and not saved['stages'] and not (folder/'context-audit.json').exists() and not (exp/'15s').exists() and not (exp/'180s').exists()
                    result.update(audit_status='independently_replayed_rejection',stages=[dict(stage='control',status='rejected',error=str(error))],limits='Control ambiguity failure reproduced from original bytes. No Go load or RSS result exists in this run.')
                    args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));return
            assert parsed==json.loads((folder/'context-audit.json').read_text())
            summary=dict(stage=name,events=parsed['events'],native_pid=parsed['native_pid'],tracepart_calls=len(parsed['call_proof']['calls']),aligned_calls=len(parsed['aligned_calls']),ap32_calls=parsed['ap32_calls'],aligned_with_ap32_parent=parsed['aligned_with_ap32_parent'],aligned_parameters=Counter(f"{c['size']}:{c['alignment']}" for c in parsed['aligned_calls']),mmap_syscalls=sum(c['call']=='mmap' for c in parsed['calls']),selected=[])
            if name=='control':
                assert parsed==saved['control'];a.control_check(parsed,[json.loads(s) for s in (folder/'native-stdout.log').read_text().splitlines()])
            else:
                assert parsed==saved[name]['ledger'];rows=a.lifecycle.snapshots(folder,parsed);assert canon(rows)==saved[name]['snapshots']
                report=json.loads((folder/'native/report.json').read_text());assert report['settings']['pid']==parsed['native_pid'] and 'vcs.revision='+a.direct.REVISION in report['build_info']
                assert a.verify.validate_events(folder/'native/exchanges.jsonl.gz',report)==saved[name]['business_events'];a.verify.validate_engine_logs(folder/'native',folder/'native-stderr.log',64,3)
                errors=[]
                try:resources=a.verify.validate_report(report,True);assert resources==saved[name]['resources']
                except ValueError as e:errors.append(str(e))
                assert errors==saved[name]['errors'];summary['errors']=errors
                warm=[q for q in report['points'] if q['phase']=='warmup' and q['at_seconds']>=6];active=[q for q in report['points'] if q['phase']=='measured'];base=max(warm,key=lambda q:q['resources']['rss']);peak=max(active,key=lambda q:q['resources']['rss']);baseline=base['resources']['rss']
                summary['rss']=dict(baseline=baseline,peak=peak['resources']['rss'],delta=peak['resources']['rss']-baseline,violations=sum(not 0<q['resources']['rss']<=baseline+67108864 for q in active),points=len(active))
                for metric,limit in a.verify.ACTIVE.items():
                    if metric!='rss':assert all(0<q['resources'][metric]<=max(w['resources'][metric] for w in warm)+limit for q in active)
                for metric,limit in a.verify.RETURN.items():assert 0<report['after_stop'][metric]<=report['idle_baseline'][metric]+limit
                chosen=[[base['phase'],base['at_seconds']],[peak['phase'],peak['at_seconds']]]
                post=report.get('post_stop_observation',[])
                if post:chosen+=[[q['phase'],q['at_seconds']] for q in (post[0],post[-2],post[-1])]
                for key in chosen:
                    row=next(r for r in rows if r['key']==key);state=a.lifecycle.replay(parsed['calls'],row['read_start_ns']);after=a.lifecycle.replay(parsed['calls'],row['read_end_ns']);before_ids={c['mmap_id'] for c in parsed['aligned_calls'] if next(f['ret']['ns'] for f in parsed['context_frames'] if f['id']==c['frame_id'])<row['read_start_ns']}
                    origins={}
                    for label in (a.lifecycle.LABEL,a.LABEL,'unresolved'):
                        segments=[(lo,hi,g) for lo,hi,owner,g in state if owner==label];origins[label]=dict(surviving_virtual_bytes=sum(hi-lo for lo,hi,g in segments),surviving_generations=len({g for lo,hi,g in segments}))
                    groups=[]
                    for c in parsed['aligned_calls']:
                        if c['mmap_id'] not in before_ids:continue
                        pieces=[(lo,hi) for lo,hi,_,g in state if g==c['mmap_id']];pieces_after=[(lo,hi) for lo,hi,_,g in after if g==c['mmap_id']]
                        groups.append(dict(mmap_id=c['mmap_id'],size=c['size'],alignment=c['alignment'],surviving_virtual_bytes=sum(hi-lo for lo,hi in pieces),endpoint_pieces_equal=pieces==pieces_after,ap32_parent=bool(set(c['parent_frame_ids'])&{f['id'] for f in parsed['context_frames'] if f['kind']==5})))
                    summary['selected'].append(dict(key=key,native_rss=row['point']['resources']['rss'],origins=origins,aligned_generations=groups,whole_vma_rss=row['groups_rss_bytes'],scope='virtual mapping replay plus separately read whole-VMA RSS; no proportional attribution or atomic claim'))
                summary['business_events']=saved[name]['business_events'];summary['checkpoints']=len(rows);totals['checkpoints']+=len(rows)
            result['stages'].append(summary)
            for k in ('events','tracepart_calls','aligned_calls','ap32_calls'):totals[k]+=summary[k]
        result['totals']=dict(totals);result['limits']='Actual new-run request/trim lineage only. No PFNs or page-status measurement in this run, no object lifecycle, no observation overhead control, no retroactive attribution of PR39 pages, no 24h acceptance.'
        args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(status=result['audit_status'],stages=[{k:v for k,v in s.items() if k!='selected'} for s in result['stages']],totals=result['totals']),indent=2))
if __name__=='__main__':main()
