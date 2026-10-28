#!/usr/bin/env python3
"""Validated direct-call mapping generations; requests are never RSS releases."""
import argparse,gzip,hashlib,json,os,re,subprocess
from collections import Counter
from pathlib import Path
import soak_callsite_control as callsite
import soak_ret_context as context
import soak_mapping_ledger as old
import soak_mapping_retention as retention
import soak_mappings as mappings
import verify_soak as verify
PAGE=4096
EXTRA={'munmap':['addr','len'],'mremap':['addr','old_len','new_len','flags','new_addr'],'madvise':['start','len_in','behavior'],'brk':['brk']}
LABEL='validated_tracepart_call'

def program(p):
    text=callsite.program(p).replace('nsecs,','nsecs(monotonic),').replace('nsecs);','nsecs(monotonic));')
    for name,args in EXTRA.items():
        for event in ('sys_enter','sys_exit'):
            fields=','.join('\\"a%d\\":%%llu'%i for i in range(len(args))) if event=='sys_enter' else '\\"value\\":%llu'
            values=','.join('(uint64)args.'+a for a in args) if event=='sys_enter' else '(uint64)args.ret'
            text+=f'tracepoint:syscalls:{event}_{name} /pid == cpid/ {{ @seq[tid] = @seq[tid] + 1; printf("{{\\"event\\":\\"{event}\\",\\"call\\":\\"{name}\\",\\"pid\\":%d,\\"tid\\":%d,\\"uid\\":%d,\\"seq\\":%llu,\\"ns\\":%llu,{fields}}}\\n",pid,tid,uid,@seq[tid],nsecs(monotonic),{values}); }}\n'
    return text

def parse(raw,p,uid):
    records=[];ledger={};boundary=[];begin=[];end=[]
    for line in raw.splitlines():
        if not line.strip():continue
        m=re.fullmatch(r'@seq\[(\d+)\]: (\d+)',line)
        if m:
            tid,n=map(int,m.groups())
            if tid in ledger:raise ValueError('duplicate ledger')
            ledger[tid]=n;continue
        r=json.loads(line)
        if r['event']=='begin':begin.append(r)
        elif r['event']=='end':end.append(r)
        else:
            records.append(r)
            if r['event']=='exec' and r['path']==p['binary']:boundary.append(r)
    if len(begin)!=1 or len(end)!=1 or begin[0]['pid']!=end[0]['pid'] or len(boundary)!=1:raise ValueError('missing identity boundary')
    pid=begin[0]['pid'];epoch=boundary[0]['ns'];threads={};calls=[];projected=[];back={};counts={}
    for r in records:
        if any(type(r[k]) is not int or not 0<=r[k]<1<<64 for k in ('pid','tid','uid','seq','ns')):raise ValueError('invalid event number')
        if r['pid']!=pid or r['uid'] not in (0,uid) or (r['ns']>=epoch and r['uid']!=uid):raise ValueError('identity mismatch')
        if r['event'] in ('sys_enter','sys_exit'):
            if r['call'] not in EXTRA:raise ValueError('unknown syscall')
            keys=['a'+str(i) for i in range(len(EXTRA[r['call']]))] if r['event']=='sys_enter' else ['value']
            if any(type(r[k]) is not int or not 0<=r[k]<1<<64 for k in keys):raise ValueError('invalid syscall number')
        elif r['event'] not in ('call','after','exec','mmap_entry','mmap_exit'):raise ValueError('unknown event')
        threads.setdefault(r['tid'],[]).append(r)
    if set(threads)!=set(ledger):raise ValueError('missing entire thread')
    for tid,rows in threads.items():
        rows.sort(key=lambda r:r['seq']);pending=None;last=-1
        if [r['seq'] for r in rows]!=list(range(1,ledger[tid]+1)):raise ValueError('missing/duplicate event')
        for r in rows:
            if r['ns']<last:raise ValueError('backward clock')
            last=r['ns'];event=r['event']
            if event not in ('sys_enter','sys_exit'):
                counts[tid]=counts.get(tid,0)+1;projected.append(dict(r,seq=counts[tid]));back[(tid,counts[tid])]=r
            if event=='exec':
                if pending is not None:raise ValueError('exec across syscall')
            elif event in ('mmap_entry','sys_enter'):
                if pending is not None:raise ValueError('nested syscall')
                pending=r
            elif event in ('mmap_exit','sys_exit'):
                name='mmap' if event=='mmap_exit' else r['call']
                if pending is None or (pending['event']=='mmap_entry' and name!='mmap') or (pending['event']=='sys_enter' and pending['call']!=name):raise ValueError('unpaired syscall')
                entry=pending;pending=None
                args=[entry['value'],entry['size'],entry['flags'],entry['tag']] if name=='mmap' else [entry['a'+str(i)] for i in range(len(EXTRA[name]))]
                if r['ns']>=epoch:calls.append(dict(call=name,id=f'{tid}:{entry["seq"]}',tid=tid,start_ns=entry['ns'],end_ns=r['ns'],args=args,value=r['value'],owner='unresolved'))
        if pending is not None:raise ValueError('unfinished syscall')
    # Full original sequence is validated above. The old call validator sees a
    # clearly identified projection; restored syscall IDs below remain original.
    projection='\n'.join([json.dumps(begin[0])]+[json.dumps(r) for r in projected]+[json.dumps(end[0])]+[f'@seq[{tid}]: {n}' for tid,n in counts.items()])
    proof=callsite.audit(projection,p,uid);by_id={c['id']:c for c in calls}
    for c in proof['calls']:
        entry=back[(c['tid'],c['mmap_entry_seq'])];key=f'{c["tid"]}:{entry["seq"]}'
        if key not in by_id:raise ValueError('validated call lacks original syscall')
        by_id[key]['owner']=LABEL;by_id[key]['validated_call_seq']=back[(c['tid'],c['call_seq'])]['seq']
    calls=prepare(calls);replay(calls,max(c['end_ns'] for c in calls))
    return dict(native_pid=pid,target_exec_ns=epoch,events=len(records),thread_ledger=ledger,call_proof=proof,calls=calls,scope='original full memory-syscall sequence plus separately identified call-validator projection; only one direct-call path is classified')

def rounded(n):return (n+PAGE-1)//PAGE*PAGE
def success(c):return c['value']<(1<<64)-4095
def span(addr,n):
    if not n:return []
    if addr%PAGE or n<0 or addr+rounded(n)>=1<<64:raise ValueError('invalid range')
    return [(addr,addr+rounded(n))]
def affected(c):
    a=c['args'];kind=c['call']
    if kind=='mmap':return span(c['value'],a[1]) if success(c) else span(a[0],a[1]) if a[3]&0x10 else []
    if kind in ('munmap','madvise'):
        # Failed unaligned advice is recorded, not used as a mapping mutation.
        return [(a[0]//PAGE*PAGE,rounded(a[0]+a[1]))] if a[1] else []
    if kind=='mremap':return span(a[0],a[1])+(span(c['value'],a[2]) if success(c) else span(a[4],a[2]) if a[3]&2 else [])
    if kind=='brk':return [(0,max(a[0],c['value']))] if a[0] else []
    raise ValueError('unknown syscall')
def prepare(calls):
    calls=sorted([dict(c,ambiguous=False) for c in calls],key=lambda c:(c['end_ns'],c['tid'],c['id']));active=[]
    for c in sorted(calls,key=lambda c:c['start_ns']):
        active=[a for a in active if a['end_ns']>=c['start_ns']]
        for a in active:
            if a['call']=='madvise' and c['call']=='madvise':continue
            if any(lo<y and x<hi for lo,hi in affected(a) for x,y in affected(c)):a['ambiguous']=c['ambiguous']=True
        active.append(c)
    return calls

def cut(state,lo,hi):
    out=[]
    for a,b,owner,gen in state:
        if a>=hi or b<=lo:out.append((a,b,owner,gen));continue
        if a<lo:out.append((a,lo,owner,gen))
        if b>hi:out.append((hi,b,owner,gen))
    return out
def invalidate(state,lo,hi):
    out=cut(state,lo,hi)
    for a,b,_,gen in state:
        if a<hi and lo<b:out.append((max(a,lo),min(b,hi),'unresolved',gen))
    return sorted(out)
def cover(lo,hi,state):
    cursor=lo;owners=set();gens=set()
    for a,b,owner,gen in sorted(state):
        if b<=cursor:continue
        if a>cursor:break
        owners.add(owner);gens.add(gen);cursor=min(hi,b)
        if cursor==hi:return (next(iter(owners)) if len(owners)==1 else 'unresolved',sorted(gens))
    return ('unresolved',[])
def replay(calls,at):
    state=[];brk=None
    for c in calls:
        if c['end_ns']>at:break
        a=c['args'];kind=c['call'];value=c['value'];owner=c['owner'] if not c['ambiguous'] else 'unresolved'
        if kind=='madvise':continue # Requests never imply unmapping or RSS release.
        if not success(c):
            # Failed mutators cannot establish a release or preserve attribution.
            for lo,hi in affected(c):state=invalidate(state,lo,hi)
            continue
        if kind=='mmap':
            lo,hi=span(value,a[1])[0]
            if not a[3]&0x10 and not c['ambiguous'] and any(x<hi and lo<y for x,y,_,_ in state):raise ValueError('non-fixed mmap overlaps known mapping')
            state=cut(state,lo,hi)+[(lo,hi,owner,c['id'])]
        elif kind=='munmap':
            if value!=0:raise ValueError('invalid munmap return')
            for lo,hi in affected(c):state=cut(state,lo,hi)
        elif kind=='mremap':
            if a[1]==0 or a[3]&~3:raise ValueError('unsupported mremap clone/DONTUNMAP flags')
            oldlo,oldhi=span(a[0],a[1])[0];origin,parents=cover(oldlo,oldhi,state)
            c['parent_generations']=parents;c['new_generation']=c['id']
            state=cut(state,oldlo,oldhi);lo,hi=span(value,a[2])[0];state=cut(state,lo,hi)
            kept=min(hi,lo+oldhi-oldlo);state.append((lo,kept,origin if not c['ambiguous'] else 'unresolved',c['id']))
            if kept<hi:state.append((kept,hi,'unresolved',c['id']))
        elif kind=='brk':
            if brk is not None and value!=brk:
                lo=min(brk,value)//PAGE*PAGE;hi=rounded(max(brk,value));state=cut(state,lo,hi)
                if value>brk:state.append((rounded(brk),rounded(value),'unresolved',c['id']))
            brk=value
        if c['ambiguous']:
            for lo,hi in affected(c):state=invalidate(state,lo,hi)
        state=sorted(state)
    return state

def attribute(raw,calls,start,end):
    before=replay(calls,start);after=replay(calls,end);proof=[];groups=Counter()
    for v in mappings.parse_smaps(raw,True)['mappings']:
        lo,hi=v['start'],v['end'];label=v['path'] if v['path'].startswith('[anon:') else v['category'];gens=[]
        if not v['path']:
            a=cover(lo,hi,before);b=cover(lo,hi,after)
            unstable=any(c['start_ns']<=end and c['end_ns']>=start and any(x<hi and lo<y for x,y in affected(c)) for c in calls)
            label=a[0] if a==b and not unstable else 'unresolved';gens=a[1] if a==b and not unstable else []
            proof.append(dict(start=lo,end=hi,rss=v['bytes']['Rss'],address_category=v['category'],request_path=label,generations=gens,overlapping_operation=unstable))
        groups[label]+=v['bytes']['Rss']
    return dict(groups_rss_bytes=dict(groups),unnamed_vmas=proof,scope='whole-VMA request origin only; no proportional RSS assignment, object or release claim')

def snapshots(folder,parsed,control=False):
    out=[];captures=[json.loads((folder/'snapshots.json').read_text())]
    if (folder/'retention-snapshots.json').exists():captures.append(json.loads((folder/'retention-snapshots.json').read_text()))
    execution=json.loads((folder/'execution.json').read_text());native=json.loads((folder/'native/report.json').read_text()) if not control else None
    if not execution['target_identity_verified'] or not execution['group_gone']:raise ValueError('snapshot identity/cleanup missing')
    if not captures[0].get('binary_inode_verified'):raise ValueError('snapshot executable inode not verified')
    for capture in captures:
        if capture['clock']!='CLOCK_MONOTONIC':raise ValueError('snapshot clock mismatch')
        for r in capture['records']:
            if Path(r['file']).is_absolute() or '..' in Path(r['file']).parts:raise ValueError('unsafe snapshot path')
            retention.timely(r,parsed['target_exec_ns']);path=folder/r['file']
            if r['pid']!=parsed['native_pid'] or str(r['start_ticks'])!=str(execution['target_identity']['start_ticks']) or callsite.sha(path.read_bytes())!=r['sha256']:raise ValueError('snapshot hash/identity mismatch')
            if control:
                if r['read_start_monotonic_ns']<r['point']['monotonic_ns']:raise ValueError('control clock mismatch')
            elif 'load_evidence_sha256' in r:
                if r['load_evidence_sha256']!=mappings.load_evidence_hash(native):raise ValueError('load mutation during retention')
            else:
                final=next(p for p in native['points'] if [p['phase'],p['at_seconds']]==r['key']);old.validate_published_point(r['point'],final)
            if capture.get('format_version')==2 and (r['published_point_sha256']!=old.point_sha(r['point']) or r['point_core_sha256']!=old.point_sha(old.point_core(r['point']))):raise ValueError('published snapshot point hash mismatch')
            if 'point_sha256' in r and r['point_sha256']!=old.point_sha(r['point']):raise ValueError('retention snapshot point hash mismatch')
            out.append(dict(key=r['key'],point=r['point'],read_start_ns=r['read_start_monotonic_ns'],read_end_ns=r['read_end_monotonic_ns'],**attribute(gzip.open(path,'rt').read(),parsed['calls'],r['read_start_monotonic_ns'],r['read_end_monotonic_ns'])))
    if not control:
        expected=[[p['phase'],p['at_seconds']] for p in native['points'] if p['phase'] in ('warmup','measured')]+[[p['phase'],p['at_seconds']] for p in native.get('post_stop_observation',[])]
        if [r['key'] for r in out]!=expected:raise ValueError('missing checkpoint snapshots')
        if native.get('post_stop_observation'):
            records=captures[-1]['records'];points=native['post_stop_observation']
            if [r['point'] for r in records]!=points:raise ValueError('retention point mismatch')
            pre=next(r for r in reversed(records) if r['point']['phase']=='poststop_gc');ack=json.loads((folder/'native/post-stop-observer-ack.json').read_text())
            expected_ack=dict(phase=pre['point']['phase'],at_seconds=pre['point']['at_seconds'],mapping_sha256=pre['sha256'],record_sha256=old.point_sha(pre),load_evidence_sha256=pre['load_evidence_sha256'])
            if ack!=expected_ack:raise ValueError('observer acknowledgment mismatch')
    return out

def validate_control(folder,parsed,rows):
    names=['held','discarded','failed_advice','retouched','hole','reused','moved','released']
    if [r['key'] for r in rows]!=names:raise ValueError('missing control checkpoints')
    base=rows[0]['point']['base'];M=1024*1024;initial=None;reusegen=None
    for r in rows:
        state=replay(parsed['calls'],r['read_start_ns']);name=r['key'];origin,gen=cover(base,base+4*M,state)
        if name in names[:4]:
            if origin!=LABEL or not gen:raise ValueError('initial call generation missing')
            if initial is None:initial=gen
            if gen!=initial:raise ValueError('madvise changed generation')
            rss=sum(v['rss'] for v in r['unnamed_vmas'] if v['start']==base and v['end']==base+4*M)
            if rss!=(0 if name in ('discarded','failed_advice') else 4*M):raise ValueError('known control RSS mismatch')
        elif name=='hole':
            if any(lo<base+3*M and base+M<hi for lo,hi,_,_ in state):raise ValueError('partial unmap not removed')
            if cover(base,base+M,state)[1]!=initial or cover(base+3*M,base+4*M,state)[1]!=initial:raise ValueError('split lost surviving generation')
        elif name=='reused':
            origin,reusegen=cover(base+M,base+3*M,state)
            if origin!='unresolved' or not reusegen or reusegen==initial:raise ValueError('reuse inherited original call attribution')
        elif name=='moved':
            current=r['point']['current'];origin,gen=cover(current,current+4*M,state)
            if origin!='unresolved' or not gen or gen==reusegen or any(lo<base+3*M and base+M<hi for lo,hi,_,_ in state):raise ValueError('mremap generation/old range incorrect')
        elif name=='released':
            current=r['point']['current']
            if any(lo<current+4*M and current<hi for lo,hi,_,_ in state):raise ValueError('released mapping remains')
    advice=[c for c in parsed['calls'] if c['call']=='madvise' and base<=c['args'][0]<base+4*M]
    if len(advice)!=2 or [c['value'] for c in advice]!=[0,(1<<64)-22]:raise ValueError('advice success/failure evidence missing')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','control','tracer','artifacts'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();a.artifacts.mkdir(parents=True,exist_ok=False);result={'status':'failed','qualifies_24h':False,'rss_budget':67108864,'stages':[]}
    try:
        os.environ['BPFTRACE_STRLEN']='256'
        if os.sysconf('SC_PAGE_SIZE')!=PAGE or callsite.sha(a.binary.read_bytes())!=callsite.BINARY_SHA:raise ValueError('frozen ELF/page size required')
        folder=a.artifacts/'control';collector=old.Collector(folder,a.control,True)
        parsed=context.launch(a.control,folder,{1:'control_site'},[str(folder.resolve())],60,a.tracer,program_builder=program,auditor=parse,poll_hook=collector)
        rows=snapshots(folder,parsed,True);validate_control(folder,parsed,rows);result['control']={'ledger':parsed,'snapshots':rows};result['stages'].append('control_passed')
        # Each stage is a fresh process. A failed resource check is retained;
        # it is never replaced by the other stage or a later warmup baseline.
        for duration in ('15s','180s'):
            folder=a.artifacts/duration;native=(folder/'native').resolve();collector=retention.Collector(folder,a.binary) if duration=='180s' else old.Collector(folder,a.binary)
            args=['--transport','3','--mode','1','--duration',duration,'--warmup','12s','--sample-interval','5s','--workers','2','--qps','10','--pool-min','16','--pool-max','64','--artifacts',str(native)]
            if duration=='180s':args+=['--post-stop-observe','120s','--diagnostic-go-scavenge','--post-stop-observer-ack']
            parsed=context.launch(a.binary,folder,{1:callsite.OWNER},args,450 if duration=='180s' else 120,a.tracer,program_builder=program,auditor=parse,poll_hook=collector)
            rows=snapshots(folder,parsed);report=json.loads((native/'report.json').read_text());stage={'ledger':parsed,'snapshots':rows,'errors':[]};result[duration]=stage
            if report['settings']['pid']!=parsed['native_pid'] or 'vcs.revision='+callsite.REVISION not in report['build_info']:raise ValueError('native report mismatch')
            stage['events']=verify.validate_events(native/'exchanges.jsonl.gz',report);verify.validate_engine_logs(native,folder/'native-stderr.log',64,3)
            try:stage['resources']=verify.validate_report(report,True)
            except ValueError as e:stage['errors'].append(str(e))
            result['stages'].append(duration+'_evidence_complete')
        result['status']='diagnostic_passed' if all(not result[d]['errors'] for d in ('15s','180s')) else 'failed'
    except (ValueError,KeyError,OSError,AssertionError,subprocess.SubprocessError) as e:result['error']=type(e).__name__+': '+str(e)
    finally:
        result['files']={str(f.relative_to(a.artifacts)):callsite.sha(f.read_bytes()) for f in a.artifacts.rglob('*') if f.is_file() and f.name!='experiment.json'};callsite.dump(a.artifacts/'experiment.json',result)
    return int(result['status']!='diagnostic_passed')
if __name__=='__main__':raise SystemExit(main())
