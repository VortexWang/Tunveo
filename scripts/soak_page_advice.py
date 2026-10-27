#!/usr/bin/env python3
"""Capture madvise requests in the same ordered mapping/RET ledger.

Advice bytes are virtual request lengths, never reclaimed RSS. Neighboring
whole-VMA RSS samples are descriptive, not single-syscall causal estimates.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess

import soak_mapping_ledger as ledger
import soak_mapping_retention as retention
import soak_mappings as mappings
import soak_ret_context as context
import verify_soak as verify

# Linux SYSCALL_DEFINE3(madvise, unsigned long, start, size_t, len_in, int, behavior).
# The actual CI tracepoint format is checked and archived before tracing.
CALL_ARGS = dict(ledger.ARGS,madvise=['start','len_in','behavior'])
ADVICE = {0:'NORMAL',1:'RANDOM',2:'SEQUENTIAL',3:'WILLNEED',4:'DONTNEED',8:'FREE',
          9:'REMOVE',10:'DONTFORK',11:'DOFORK',12:'MERGEABLE',13:'UNMERGEABLE',
          14:'HUGEPAGE',15:'NOHUGEPAGE',16:'DONTDUMP',17:'DODUMP',18:'WIPEONFORK',
          19:'KEEPONFORK',20:'COLD',21:'PAGEOUT',22:'POPULATE_READ',23:'POPULATE_WRITE',
          24:'DONTNEED_LOCKED',25:'COLLAPSE',100:'HWPOISON',101:'SOFT_OFFLINE'}


def program(plan):
    return ledger.program(plan,call_args=CALL_ARGS)


def parse(raw,plan,uid):
    result=ledger.parse(raw,plan,uid,call_args=CALL_ARGS)
    result['scope'] += '; paired madvise requests in the same full per-thread sequence; no byte-to-RSS conversion'
    return result


def behavior(raw):
    low=raw&0xffffffff
    signed=low if low<1<<31 else low-(1<<32)
    if raw not in (low,signed%(1<<64)):
        raise ValueError('invalid madvise behavior extension')
    return signed


def describe(call,mapping_calls):
    addr,length,raw=call['args'];kind=behavior(raw)
    value=call['value']
    if value==0:status='succeeded';errno=None
    elif (1<<64)-4095<=value<1<<64:status='failed';errno=(1<<64)-value
    else:raise ValueError('invalid madvise return')
    if addr+length>1<<64:raise ValueError('madvise range overflow')
    if status=='succeeded' and addr%ledger.PAGE:raise ValueError('successful unaligned madvise')
    lo=addr//ledger.PAGE*ledger.PAGE;hi=ledger.rounded(addr+length) if length else lo
    before=ledger.cover(lo,hi,ledger.replay(mapping_calls,call['start_ns'])) if length else ('empty',[])
    after=ledger.cover(lo,hi,ledger.replay(mapping_calls,call['end_ns'])) if length else ('empty',[])
    changed=any(c['start_ns']<=call['end_ns'] and c['end_ns']>=call['start_ns'] and
                any(a<hi and lo<b for a,b in ledger.affected(c)) for c in mapping_calls)
    stable=before==after and not changed
    origin=before[0] if stable else 'unresolved'
    band=next((name for name,(a,b) in mappings.RANGES.items() if a<=lo<hi<=b),'other_address')
    return dict(id=call['id'],tid=call['tid'],start_ns=call['start_ns'],end_ns=call['end_ns'],
        address=addr,requested_length=length,page_range=[lo,hi],behavior_raw=raw,
        behavior=kind,advice=ADVICE.get(kind,'OTHER'),status=status,errno=errno,
        request_origin=origin,generations=before[1] if stable else [],
        mapping_changed_during_call=changed,address_band=band,
        observed_contexts=call['contexts'],
        scope='successful request is not measured release; failed requests can have partial effects; origin is mapping request path only')


def validate_control(rows,capture,calls):
    names=['held','discarded','failed','retouched','reused','reused_discarded','released']
    if [x['key'] for x in rows]!=names:raise ValueError('missing advice control stage')
    base=rows[0]['point']['base'];end=base+4*1024*1024
    expected=[4*1024*1024,0,0,4*1024*1024,4*1024*1024,0,0]
    generations=[]
    for i,row in enumerate(rows):
        if row['point']['base']!=base:raise ValueError('advice control base changed')
        vmas=[v for v in row['unnamed_vmas'] if v['start']<end and base<v['end']]
        if sum(v['rss'] for v in vmas)!=expected[i]:raise ValueError('advice control RSS mismatch')
        rec=capture['records'][i];state=ledger.replay(calls,rec['read_start_monotonic_ns'])
        cover=ledger.cover(base,end,state);generations.append(cover[1])
        if i<6:
            owner='trace_switch' if i<4 else 'internal_allocator'
            if len(vmas)!=1 or (vmas[0]['start'],vmas[0]['end'],cover[0])!=(base,end,owner):
                raise ValueError('advice control generation/owner/VMA mismatch')
        elif vmas:raise ValueError('released control mapping remains')
    if not generations[0] or any(g!=generations[0] for g in generations[:4]):
        raise ValueError('madvise incorrectly changed mapping generation')
    if not generations[4] or generations[4]==generations[0] or generations[5]!=generations[4]:
        raise ValueError('reused control inherited old allocation')
    advice=[c for c in calls if c['call']=='madvise']
    if len(advice)!=3 or [c['value'] for c in advice]!=[0,(1<<64)-22,0]:
        raise ValueError('missing control madvise success/failure pairs')
    if [c['args'] for c in advice]!=[[base,4*1024*1024,4],[base+1,4096,4],[base,4*1024*1024,4]]:
        raise ValueError('control madvise arguments differ')


def snapshot_rows(folder,parsed,race):
    family='observed_race_runtime' if race else 'observed_control_context'
    mapping_calls=ledger.prepare([dict(c,owner=family if c['contexts'] else 'unresolved')
                                 for c in parsed['calls'] if c['call']!='madvise'])
    captures=[json.loads((folder/'snapshots.json').read_text())]
    if (folder/'retention-snapshots.json').exists():
        captures.append(json.loads((folder/'retention-snapshots.json').read_text()))
    out=[]
    for capture in captures:
        for rec in capture['records']:
            path=folder/rec['file']
            if hashlib.sha256(path.read_bytes()).hexdigest()!=rec['sha256']:
                raise ValueError('advice snapshot hash mismatch')
            raw=gzip.open(path,'rt').read();start,end=rec['read_start_monotonic_ns'],rec['read_end_monotonic_ns']
            attributed=ledger.attribute(raw,race,mapping_calls,start,end)
            proof={(v['start'],v['end']):v for v in attributed['unnamed_vmas']}
            vmas=[]
            for vma in mappings.parse_smaps(raw,race)['mappings']:
                lo,hi=vma['start'],vma['end'];a=ledger.cover(lo,hi,ledger.replay(mapping_calls,start))
                b=ledger.cover(lo,hi,ledger.replay(mapping_calls,end))
                inflight=any(c['start_ns']<=end and c['end_ns']>=start and
                    any(x<hi and lo<y for x,y in ledger.affected(c)) for c in mapping_calls)
                item=dict(start=lo,end=hi,rss=vma['bytes']['Rss'],path=vma['path'],
                    category=vma['category'],generations=a[1] if a==b and not inflight else [])
                item['request_origin']=proof.get((lo,hi),{}).get('owner','not_unnamed_anonymous')
                vmas.append(item)
            out.append(dict(key=rec['key'],read_start_ns=start,read_end_ns=end,
                point_sha256=ledger.point_sha(rec['point']),file=rec['file'],sha256=rec['sha256'],
                statm_rss=rec['point'].get('resources',{}).get('rss'),vmas=vmas))
    out.sort(key=lambda x:x['read_start_ns'])
    return out


def audit_advice(folder,parsed,race):
    family='observed_race_runtime' if race else 'observed_control_context'
    mapping_calls=ledger.prepare([dict(c,owner=family if c['contexts'] else 'unresolved')
                                 for c in parsed['calls'] if c['call']!='madvise'])
    snapshots=snapshot_rows(folder,parsed,race)
    advice=[describe(c,mapping_calls) for c in parsed['calls'] if c['call']=='madvise']
    for event in advice:
        before=[i for i,s in enumerate(snapshots) if s['read_end_ns']<=event['start_ns']]
        after=[i for i,s in enumerate(snapshots) if s['read_start_ns']>=event['end_ns']]
        bi,ai=(before[-1] if before else None),(after[0] if after else None)
        event.update(before_snapshot=bi,after_snapshot=ai,
            read_overlap_snapshots=[i for i,s in enumerate(snapshots) if
                s['read_start_ns']<=event['end_ns'] and s['read_end_ns']>=event['start_ns']])
        event['neighbor_whole_vma_deltas']=[]
        if bi is None or ai is None:continue
        old,new=snapshots[bi],snapshots[ai];lo,hi=event['page_range']
        signature=lambda v:(v['start'],v['end'],v['path'],v['request_origin'],tuple(v['generations']))
        previous={signature(v):v for v in old['vmas'] if v['generations']}
        for v in new['vmas']:
            key=signature(v)
            if not (v['start']<hi and lo<v['end']) or key not in previous:continue
            changed=any(c['start_ns']<=new['read_end_ns'] and c['end_ns']>=old['read_start_ns'] and
                any(a<v['end'] and v['start']<b for a,b in ledger.affected(c)) for c in mapping_calls)
            if changed:continue
            event['neighbor_whole_vma_deltas'].append(dict(start=v['start'],end=v['end'],
                category=v['category'],path=v['path'],generations=v['generations'],
                before_rss=previous[key]['rss'],after_rss=v['rss'],
                rss_delta=v['rss']-previous[key]['rss'],
                other_overlapping_advice=[c['id'] for c in advice if c['id']!=event['id'] and
                    old['read_end_ns']<=c['end_ns']<=new['read_start_ns'] and
                    c['page_range'][0]<v['end'] and v['start']<c['page_range'][1]]))
    counts=Counter((e['advice'],e['status'],e['request_origin'],e['address_band']) for e in advice)
    return dict(events=advice,snapshots=snapshots,
        counts=[dict(advice=k[0],status=k[1],request_origin=k[2],address_band=k[3],count=v) for k,v in sorted(counts.items())],
        scope='virtual madvise requests with mapping generations at call time; whole-VMA neighboring RSS only, no prorating or per-call reclaimed bytes; no process_madvise/mprotect capture')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for flag in ('binary','control','tracer','artifacts'):p.add_argument('--'+flag,type=Path,required=True)
    a=p.parse_args();a.artifacts.mkdir(parents=True,exist_ok=False)
    result=dict(status='failed',pilot_only=True,qualifies_24h=False,stages=[])
    try:
        if os.sysconf('SC_PAGE_SIZE')!=ledger.PAGE:raise ValueError('only 4096-byte pages supported')
        folder=a.artifacts/'control'
        parsed=context.launch(a.control,folder,ledger.CONTROL,[str(folder.resolve())],45,a.tracer,
            program_builder=program,auditor=parse,poll_hook=ledger.Collector(folder,a.control,True))
        rows=ledger.audit_snapshots(folder,parsed,False,True,control_validator=validate_control)
        result['control']=dict(ledger=parsed,snapshots=rows,advice=audit_advice(folder,parsed,False))
        result['stages'].append('advice_control_passed')
        binary=a.binary.resolve();info=json.loads(subprocess.check_output([str(binary),'--describe']))
        if not mappings.supported(info):raise ValueError('supported race build required')
        folder=a.artifacts/'pilot';native=(folder/'native').resolve()
        parsed=context.launch(binary,folder,context.SYMBOLS,
            ['--transport','3','--mode','1','--duration','180s','--warmup','12s',
             '--sample-interval','5s','--workers','2','--qps','10','--pool-min','16','--pool-max','64',
             '--post-stop-observe','120s','--diagnostic-go-scavenge','--post-stop-observer-ack',
             '--artifacts',str(native)],450,a.tracer,program_builder=program,auditor=parse,
             poll_hook=retention.Collector(folder,binary))
        report=json.loads((native/'report.json').read_text())
        if report['build_info']!=info['build_info'] or report['settings']['pid']!=parsed['native_pid']:
            raise ValueError('build/PID mismatch')
        result.update(description=info,pilot=dict(ledger=parsed,snapshots=ledger.audit_snapshots(folder,parsed,True)))
        result['stages'].append('mapping_audit_passed')
        result['retention']=retention.audit_retention(folder,parsed,report)
        retention.add_load_comparisons(folder,parsed,report,result['retention'])
        result['stages'].append('retention_audit_passed')
        result['advice']=audit_advice(folder,parsed,True)
        result['stages'].append('advice_audit_passed')
        result['events']=verify.validate_events(native/'exchanges.jsonl.gz',report)
        verify.validate_engine_logs(native,folder/'native-stderr.log',64,3)
        result['acceptance']=verify.validate_report(report,True)
        result['status']='diagnostic_passed'
    except (ValueError,KeyError,OSError,AssertionError,subprocess.SubprocessError) as error:
        result['error']=type(error).__name__+': '+str(error)
    finally:context.dump(a.artifacts/'experiment.json',result)
    return int(result['status']!='diagnostic_passed')


if __name__=='__main__':raise SystemExit(main())
