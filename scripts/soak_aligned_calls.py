#!/usr/bin/env python3
"""Qualified aligned-call request lineage; never object or physical RSS ownership."""
import argparse,json,os,re,subprocess
from collections import Counter
from pathlib import Path
import soak_callsite_control as direct
import soak_call_lifecycle as lifecycle
import soak_ret_context as context
import soak_mapping_ledger as ledger
import soak_mapping_retention as retention
import verify_soak as verify

ALIGNED='_ZN11__sanitizer28MmapAlignedOrDieOnFatalErrorEmmPKc'
BATCH='_ZN11__sanitizer20SizeClassAllocator32INS_4AP32EE13AllocateBatchEPNS_14AllocatorStatsEPNS_30SizeClassAllocator32LocalCacheIS2_EEm'
LABEL='validated_aligned_request'

def symbols(native=True):
    return {1:direct.OWNER,4:ALIGNED,5:BATCH} if native else {1:'control_site',4:'control_aligned',5:'control_batch'}

def qualify(p):
    binary=Path(p['binary']);raw=binary.read_bytes();out={}
    native=p['functions']['1']['symbol']==direct.OWNER
    if native and direct.sha(raw)!=direct.BINARY_SHA:raise ValueError('frozen ELF required')
    for kind in ('4','5'):
        f=p['functions'][kind]
        if f['symbol']!=symbols(native)[int(kind)] or f['tail_exits']:raise ValueError('unqualified context symbol/tail')
        # Re-disassemble every byte, rather than accepting supplied offsets.
        actual=subprocess.check_output(['objdump','-dz','--insn-width=16','--disassemble='+f['symbol'],str(binary)],text=True)
        if actual!=f['disassembly'] or context.ret_sites(actual,f['address'],f['size'])!=f['ret_offsets']:raise ValueError('context layout mismatch')
        offset=direct.file_offset(binary,f['address'],f['size']);data=raw[offset:offset+f['size']]
        for r in f['ret_offsets']:
            if data[r:r+1]!=b'\xc3':raise ValueError('plain RET required')
        if native and (f['address'],f['size'])!=({'4':(0x412330,0x196),'5':(0x4339a0,0xfb)}[kind]):raise ValueError('frozen context mismatch')
        out[kind]=dict(address=f['address'],size=f['size'],file_offset=offset,sha256=direct.sha(data),ret_offsets=f['ret_offsets'])
    return out

def program(p):
    qualify(p);text=lifecycle.program(p)
    for kind in ('4','5'):
        f=p['functions'][kind]
        for event,offset in [('context_entry',0)]+[('context_ret',n) for n in f['ret_offsets']]:
            site=f['address']+offset
            fmt=json.dumps(dict(event=event,kind=int(kind),site=site))[:-1]+',"pid":%d,"tid":%d,"uid":%d,"seq":%llu,"ns":%llu,"sp":%llu,"a0":%llu,"a1":%llu,"a2":%llu,"a3":%llu,"value":%llu}\\n'
            quoted=fmt.replace('"','\\"')
            regs=','.join('reg("'+r+'")' for r in ('di','si','dx','cx')) if event=='context_entry' else '0,0,0,0'
            text+=f'uprobe:{p["binary"]}:{f["symbol"]}+0x{offset:x} /pid == cpid/ {{ @seq[tid] = @seq[tid] + 1; printf("{quoted}",pid,tid,uid,@seq[tid],nsecs(monotonic),reg("sp"),{regs},reg("ax")); }}\n'
    return text

def split(raw):
    records=[];counts={};bookends=[]
    for line in raw.splitlines():
        if not line.strip():continue
        m=re.fullmatch(r'@seq\[(\d+)\]: (\d+)',line)
        if m:
            tid,n=map(int,m.groups())
            if tid in counts:raise ValueError('duplicate full ledger')
            counts[tid]=n;continue
        row=json.loads(line)
        if row['event'] in ('begin','end'):bookends.append(row)
        else:records.append(row)
    if len(bookends)!=2 or Counter(r['event'] for r in bookends)!=Counter(['begin','end']):raise ValueError('incomplete bookends')
    return records,counts,bookends

def project(records,counts,bookends):
    threads={};projected=[];back={};numbers={}
    for r in records:
        if any(type(r[k]) is not int or not 0<=r[k]<1<<64 for k in ('pid','tid','uid','seq','ns')):raise ValueError('invalid full sequence number')
        threads.setdefault(r['tid'],[]).append(r)
    if set(threads)!=set(counts):raise ValueError('missing full thread')
    for tid,rows in threads.items():
        rows.sort(key=lambda r:r['seq'])
        if [r['seq'] for r in rows]!=list(range(1,counts[tid]+1)):raise ValueError('full sequence gap/duplicate')
        if any(a['ns']>b['ns'] for a,b in zip(rows,rows[1:])):raise ValueError('full clock reversed')
        for r in rows:
            if r['event'] in ('context_entry','context_ret'):continue
            n=numbers[tid]=numbers.get(tid,0)+1;back[(tid,n)]=r['seq'];projected.append(dict(r,seq=n))
    raw='\n'.join([json.dumps(r) for r in bookends+projected]+[f'@seq[{t}]: {n}' for t,n in numbers.items()])
    return raw,back

def match_frames(records,p,uid,pid,epoch,calls):
    frames=[];threads={};by_tid={}
    for c in calls:by_tid.setdefault(c['tid'],[]).append(c)
    for r in records:
        if r['pid']!=pid or (r['ns']>=epoch and r['uid']!=uid) or (r['ns']<epoch and r['uid'] not in (0,uid)):raise ValueError('full identity mismatch')
        if r['event'] in ('context_entry','context_ret'):
            if r['ns']<=epoch:raise ValueError('context before target exec')
            if any(type(r[k]) is not int or not 0<=r[k]<1<<64 for k in ('kind','site','sp','a0','a1','a2','a3','value')):raise ValueError('invalid context number')
            kind=str(r['kind'])
            if kind not in ('4','5'):raise ValueError('unknown context kind')
            f=p['functions'][kind];sites=[f['address']] if r['event']=='context_entry' else [f['address']+n for n in f['ret_offsets']]
            if r['site'] not in sites:raise ValueError('unplanned context instruction')
            threads.setdefault(r['tid'],[]).append(r)
    for tid,rows in threads.items():
        stack=[]
        for r in sorted(rows,key=lambda r:r['seq']):
            if r['event']=='context_entry':
                if stack and r['sp']>=stack[-1]['entry']['sp']:raise ValueError('non-nested context stack')
                stack.append(dict(id=f'{tid}:{r["seq"]}',kind=r['kind'],entry=r,parents=[s['id'] for s in stack]))
            else:
                if not stack:raise ValueError('context RET without entry')
                frame=stack.pop();e=frame['entry']
                if (e['kind'],e['sp'])!=(r['kind'],r['sp']):raise ValueError('context RET kind/SP mismatch')
                frame['ret']=r;frame['syscall_ids']=[]
                for c in by_tid.get(tid,[]):
                    a,b=c['start_ns'],c['end_ns']
                    # Equal timestamps cannot establish ordering across this boundary.
                    if a<=r['ns'] and b>=e['ns']:
                        if not e['ns']<a<=b<r['ns']:raise ValueError('syscall crosses context boundary')
                        frame['syscall_ids'].append(c['id'])
                frames.append(frame)
        if stack:raise ValueError('unfinished context')
    return sorted(frames,key=lambda f:(f['entry']['ns'],f['id']))

def validate_aligned(frame,calls):
    e=frame['entry'];r=frame['ret'];size,alignment=e['a0'],e['a1'];pointer=r['value']
    if any(n<4096 or n&(n-1) for n in (size,alignment)):raise ValueError('unsupported aligned parameters')
    own=[c for c in calls if c['id'] in frame['syscall_ids']]
    maps=[c for c in own if c['call']=='mmap'];unmaps=[c for c in own if c['call']=='munmap']
    if len(maps)!=1 or len(own)!=len(maps)+len(unmaps) or any(c['ambiguous'] or not lifecycle.success(c) for c in own):raise ValueError('aligned syscall coverage/ambiguity/failure')
    m=maps[0];base=m['value'];total=lifecycle.rounded(size+alignment)
    if m['args']!=[0,total,3,34] or pointer!=(base+alignment-1)//alignment*alignment:raise ValueError('aligned mmap/return mismatch')
    end=pointer+lifecycle.rounded(size)
    expected=sorted((a,b) for a,b in ((base,pointer),(end,base+total)) if a<b)
    actual=[]
    for u in unmaps:
        if u['value']!=0 or u['start_ns']<=m['end_ns']:raise ValueError('aligned cleanup ordering/return')
        actual.append((u['args'][0],u['args'][0]+lifecycle.rounded(u['args'][1])))
    if sorted(actual)!=expected:raise ValueError('aligned prefix/suffix partition mismatch')
    state=lifecycle.replay(calls,r['ns']);survivors=[(a,b,owner,gen) for a,b,owner,gen in state if gen==m['id']]
    if [(a,b) for a,b,_,_ in survivors]!=[(pointer,end)]:raise ValueError('aligned survivor generation mismatch')
    return dict(frame_id=frame['id'],tid=e['tid'],entry_seq=e['seq'],return_seq=r['seq'],size=size,alignment=alignment,tag_pointer=e['a2'],pointer=pointer,mmap_id=m['id'],mmap_args=m['args'],trim_syscall_ids=[u['id'] for u in unmaps],surviving_at_return_bytes=end-pointer,parent_frame_ids=frame['parents'])

def audit(raw,p,uid):
    layout=qualify(p);records,counts,ends=split(raw);projection,back=project(records,counts,ends)
    parsed=lifecycle.parse(projection,p,uid)
    for c in parsed['calls']:
        tid,n=map(int,c['id'].split(':'));c['id']=f'{tid}:{back[(tid,n)]}'
        if 'validated_call_seq' in c:c['validated_call_seq']=back[(tid,c['validated_call_seq'])]
        if 'parent_generations' in c:c['parent_generations']=[f'{tid0}:{back[(int(tid0),int(seq))]}' for tid0,seq in (s.split(':') for s in c['parent_generations'])]
        if 'new_generation' in c:c['new_generation']=c['id']
    frames=match_frames(records,p,uid,parsed['native_pid'],parsed['target_exec_ns'],parsed['calls'])
    aligned=[validate_aligned(f,parsed['calls']) for f in frames if f['kind']==4]
    batches=[f for f in frames if f['kind']==5]
    if not aligned or not batches:raise ValueError('candidate path not observed')
    ids={a['mmap_id'] for a in aligned}
    for c in parsed['calls']:
        if c['id'] in ids:
            if c['owner']!= 'unresolved':raise ValueError('conflicting direct-call attribution')
            c['owner']=LABEL
    parsed.update(events=len(records),thread_ledger=counts,context_layout=layout,context_frames=frames,aligned_calls=aligned,ap32_calls=len(batches),aligned_with_ap32_parent=sum(any(f['id'] in a['parent_frame_ids'] for f in batches) for a in aligned),projection_note='TracePart call_proof uses renumbered projection; full memory calls and context frames use original raw TID:seq',scope='qualified request-origin and trim lineage only; no object/cache/free or physical RSS ownership')
    lifecycle.replay(parsed['calls'],max(c['end_ns'] for c in parsed['calls']))
    return parsed

def control_check(parsed,expected):
    key=lambda r:(r['tid'],r['size'],r['alignment'],r['pointer'])
    if len(expected)!=32 or len({r['tid'] for r in expected})!=4 or sorted(map(key,expected))!=sorted(map(key,parsed['aligned_calls'])):raise ValueError('known control mismatch')
    if parsed['ap32_calls']!=32 or parsed['aligned_with_ap32_parent']!=32:raise ValueError('known parent controls mismatch')
    frames={f['id']:f for f in parsed['context_frames']}
    for a in parsed['aligned_calls']:
        parents=[frames[i] for i in a['parent_frame_ids'] if frames[i]['kind']==5]
        if len(parents)!=1 or parents[0]['ret']['value']!=a['pointer']:raise ValueError('known parent return mismatch')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','control','tracer','artifacts'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();a.artifacts.mkdir(parents=True,exist_ok=False);result=dict(status='failed',qualifies_24h=False,rss_budget=67108864,historical_failures_retained=True,stages=[])
    try:
        os.environ['BPFTRACE_STRLEN']='256'
        if os.sysconf('SC_PAGE_SIZE')!=4096 or direct.sha(a.binary.read_bytes())!=direct.BINARY_SHA:raise ValueError('frozen ELF/page size required')
        folder=a.artifacts/'control';parsed=context.launch(a.control,folder,symbols(False),[],60,a.tracer,program_builder=program,auditor=audit)
        control_check(parsed,[json.loads(s) for s in (folder/'native-stdout.log').read_text().splitlines()]);result['control']=parsed;result['stages'].append('control_passed')
        for duration in ('15s','180s'):
            folder=a.artifacts/duration;native=(folder/'native').resolve();collector=retention.Collector(folder,a.binary) if duration=='180s' else ledger.Collector(folder,a.binary)
            args=['--transport','3','--mode','1','--duration',duration,'--warmup','12s','--sample-interval','5s','--workers','2','--qps','10','--pool-min','16','--pool-max','64','--artifacts',str(native)]
            if duration=='180s':args+=['--post-stop-observe','120s','--diagnostic-go-scavenge','--post-stop-observer-ack']
            parsed=context.launch(a.binary,folder,symbols(),args,450 if duration=='180s' else 120,a.tracer,program_builder=program,auditor=audit,poll_hook=collector)
            rows=lifecycle.snapshots(folder,parsed);report=json.loads((native/'report.json').read_text());stage=dict(ledger=parsed,snapshots=rows,errors=[]);result[duration]=stage
            if report['settings']['pid']!=parsed['native_pid'] or 'vcs.revision='+direct.REVISION not in report['build_info']:raise ValueError('native report identity mismatch')
            stage['business_events']=verify.validate_events(native/'exchanges.jsonl.gz',report);verify.validate_engine_logs(native,folder/'native-stderr.log',64,3)
            try:stage['resources']=verify.validate_report(report,True)
            except ValueError as e:stage['errors'].append(str(e))
            result['stages'].append(duration+'_evidence_complete')
        result['status']='diagnostic_passed' if all(not result[d]['errors'] for d in ('15s','180s')) else 'failed'
    except (ValueError,KeyError,OSError,AssertionError,subprocess.SubprocessError) as e:result['error']=type(e).__name__+': '+str(e)
    finally:
        result['files']={str(f.relative_to(a.artifacts)):direct.sha(f.read_bytes()) for f in a.artifacts.rglob('*') if f.is_file() and f.name!='experiment.json'};direct.dump(a.artifacts/'experiment.json',result)
    return int(result['status']!='diagnostic_passed')
if __name__=='__main__':raise SystemExit(main())
