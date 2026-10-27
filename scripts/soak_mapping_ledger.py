#!/usr/bin/env python3
"""Paired mmap/munmap/mremap/brk ledger and whole-VMA context attribution."""
import argparse,gzip,hashlib,json,math,os,re,subprocess,time
from pathlib import Path
import soak_ret_context as context
import soak_mappings as mappings
import verify_soak as verify
PAGE=4096
CONTROL={1:'control_trace',2:'control_other',3:'control_mmap'}
ARGS={'mmap':['addr','len','prot','flags','fd','off'],'munmap':['addr','len'],
      'mremap':['addr','old_len','new_len','flags','new_addr'],'brk':['brk']}


def program(p):
    text=context.program(p).replace('nsecs,','nsecs(monotonic),')
    for call,names in ARGS.items():
        fields=','.join('\\"a%d\\":%%llu'%i for i in range(len(names)))
        values=', '.join('args->'+n for n in names)
        for event in ('sys_enter','sys_exit'):
            extra=','+fields if event=='sys_enter' else ',\\"value\\":%llu'
            vals=', '+values if event=='sys_enter' else ', args->ret'
            text+='tracepoint:syscalls:%s_%s /pid == cpid/ { @seq[tid] = @seq[tid] + 1; printf("{\\"event\\":\\"%s\\",\\"call\\":\\"%s\\",\\"pid\\":%%d,\\"tid\\":%%d,\\"uid\\":%%d,\\"seq\\":%%llu,\\"ns\\":%%llu%s}\\n", pid, tid, uid, @seq[tid], nsecs(monotonic)%s); }\n'%(event,call,event,call,extra,vals)
    text+='tracepoint:sched:sched_process_exec /pid == cpid/ { @seq[tid] = @seq[tid] + 1; printf("{\\"event\\":\\"exec\\",\\"filename\\":\\"%s\\",\\"pid\\":%d,\\"tid\\":%d,\\"uid\\":%d,\\"seq\\":%llu,\\"ns\\":%llu}\\n", str(args->filename), pid, tid, uid, @seq[tid], nsecs(monotonic)); }\n'
    return text


def parse(raw,p,uid):
    records=[];ledger={};begin=[];end=[]
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
        else:records.append(r)
    if len(begin)!=1 or len(end)!=1 or begin[0]['pid']!=end[0]['pid']:raise ValueError('incomplete capture')
    pid=begin[0]['pid'];threads={};target_exec=[r for r in records if r['event']=='exec' and r['filename']==p['binary']]
    if len(target_exec)!=1:raise ValueError('target exec epoch not unique')
    epoch=target_exec[0]['ns']
    if any(r['event']=='exec' and r is not target_exec[0] and r['ns']>=epoch for r in records):raise ValueError('exec after target image')
    calls=[];epochs=[];wrappers={};wrapper_sys={};counts={}
    for r in records:
        for key in ('pid','tid','uid','seq','ns'):
            if type(r[key]) is not int or not 0<=r[key]<1<<64:raise ValueError('invalid unsigned event field')
        if r['event'] in ('sys_enter','sys_exit'):
            keys=['a'+str(i) for i in range(len(ARGS[r['call']]))] if r['event']=='sys_enter' else ['value']
            if any(type(r[k]) is not int or not 0<=r[k]<1<<64 for k in keys):raise ValueError('invalid syscall field')
        if r['pid']!=pid or r['uid'] not in (0,uid) or (r['ns']>=epoch and r['uid']!=uid):raise ValueError('process/UID mismatch')
        threads.setdefault(r['tid'],[]).append(r)
    if threads.keys()!=ledger.keys():raise ValueError('missing whole thread')
    for tid,rows in threads.items():
        rows.sort(key=lambda r:r['seq']);stack=[];pending=None;previous=-1
        if [r['seq'] for r in rows]!=list(range(1,ledger[tid]+1)):raise ValueError('missing/duplicate event sequence')
        for r in rows:
            if r['ns']<previous:raise ValueError('backward clock')
            previous=r['ns'];event=r['event']
            if event=='exec':
                if stack or pending:raise ValueError('exec with open observed calls')
                epochs.append(r);continue
            if event in ('entry','ret','tail_exit'):
                if r['ns']<epoch:raise ValueError('context before target exec')
                f=p['functions'][str(r['kind'])]
                allowed=[f['address']] if event=='entry' else [f['address']+x for x in f['ret_offsets']] if event=='ret' else [f['address']+x['offset'] for x in f.get('tail_exits',[])]
                if r['site'] not in allowed:raise ValueError('unplanned instruction')
                if event=='entry':
                    if stack and r['sp']>stack[-1]['sp']:raise ValueError('non-nested stack')
                    stack.append(r)
                else:
                    if not stack:raise ValueError('exit without entry')
                    entry=stack.pop()
                    if (entry['kind'],entry['sp'])!=(r['kind'],r['sp']):raise ValueError('exit identity/SP mismatch')
                    counts[str(r['kind'])]=counts.get(str(r['kind']),0)+1
                    if r['kind']==3:wrappers[(tid,entry['seq'])]=(entry,r)
            elif event=='sys_enter':
                if pending is not None or r['call'] not in ARGS:raise ValueError('unpaired syscall entry')
                pending=(r,[(x['kind'],x['seq']) for x in stack])
            elif event=='sys_exit':
                if pending is None or pending[0]['call']!=r['call']:raise ValueError('unpaired syscall exit')
                entry,ctx=pending;pending=None
                if ctx!=[(x['kind'],x['seq']) for x in stack]:raise ValueError('context changed inside syscall')
                call=dict(call=r['call'],tid=tid,id=f'{tid}:{entry["seq"]}',start_ns=entry['ns'],end_ns=r['ns'],args=[entry['a'+str(i)] for i in range(len(ARGS[r['call']]))],value=r['value'],contexts=ctx)
                observed={k for k,s in ctx if k!=3}
                call['owner']='trace_switch' if observed=={1} else 'internal_allocator' if observed=={2} else 'mixed_context_path' if observed else 'unresolved'
                if r['ns']>=epoch:calls.append(call)
                if r['call']=='mmap':
                    for kind,seq in ctx:
                        if kind==3:wrapper_sys.setdefault((tid,seq),[]).append(call)
            else:raise ValueError('unknown record')
        if stack or pending is not None:raise ValueError('open context/syscall at exit')
    for key,(entry,ret) in wrappers.items():
        sys=wrapper_sys.get(key,[])
        if len(sys)!=1 or sys[0]['args'][1]!=entry['size'] or sys[0]['value']!=ret['value']:raise ValueError('wrapper/syscall value or size mismatch')
    return dict(native_pid=pid,target_exec_ns=epoch,events=len(records),thread_ledger=ledger,context_pairs=counts,calls=sorted(calls,key=lambda r:(r['end_ns'],r['tid'],r['id'])),epochs=epochs,scope='full captured memory-syscall pairs after unique target exec; lexical contexts complete; non-syscall exec mappings/heap origins remain unknown')


def rounded(n):return ((n+PAGE-1)//PAGE)*PAGE

def remove(intervals,lo,hi):
    result=[]
    for a,b,owner,gen in intervals:
        if b<=lo or a>=hi:result.append((a,b,owner,gen));continue
        if a<lo:result.append((a,lo,owner,gen))
        if b>hi:result.append((hi,b,owner,gen))
    return result


def success(call):return call['value']<(1<<64)-4095


def affected(call):
    a=call['args'];kind=call['call'];out=[]
    if kind=='mmap':
        if success(call):out.append((call['value'],call['value']+rounded(a[1])))
        elif a[3]&0x10:out.append((a[0],a[0]+rounded(a[1])))
    elif kind=='munmap':out.append((a[0],a[0]+rounded(a[1])))
    elif kind=='brk' and a[0]:out.append((0,max(a[0],call['value'])))
    elif kind=='mremap':
        out.append((a[0],a[0]+rounded(a[1])))
        if success(call):out.append((call['value'],call['value']+rounded(a[2])))
        elif a[3]&2:out.append((a[4],a[4]+rounded(a[2])))
    return out


def prepare(calls):
    calls=sorted((dict(c) for c in calls),key=lambda c:(c['end_ns'],c['tid'],c['id']))
    for c in calls:c['ambiguous']=False
    ordered=sorted(calls,key=lambda c:c['start_ns'])
    for i,a in enumerate(ordered):
        for b in ordered[i+1:]:
            if b['start_ns']>a['end_ns']:break
            if any(lo<z and x<hi for lo,hi in affected(a) for x,z in affected(b)):
                a['ambiguous']=b['ambiguous']=True
    return calls


def replay(calls,at):
    intervals=[];brk=None
    for c in calls:
        if c['end_ns']>at:break
        a=c['args'];kind=c['call'];value=c['value'];owner=c['owner'] if not c['ambiguous'] else 'unresolved'
        if kind=='mmap':
            if success(c):
                lo=value;hi=lo+rounded(a[1]);intervals=remove(intervals,lo,hi);intervals.append((lo,hi,owner,c['id']))
            elif a[3]&0x10:intervals=remove(intervals,a[0],a[0]+rounded(a[1]))
        elif kind=='munmap':intervals=remove(intervals,a[0],a[0]+rounded(a[1]))
        elif kind=='mremap':
            intervals=remove(intervals,a[0],a[0]+rounded(a[1]))
            if success(c):
                intervals=remove(intervals,value,value+rounded(a[2]));intervals.append((value,value+rounded(a[2]),'unresolved',c['id']))
            elif a[3]&2:intervals=remove(intervals,a[4],a[4]+rounded(a[2]))
        elif kind=='brk':
            if brk is not None and value!=brk:intervals=remove(intervals,min(brk,value)//PAGE*PAGE,rounded(max(brk,value)))
            brk=value
    return sorted(intervals)


def cover(lo,hi,intervals):
    cursor=lo;owners=set();gens=set()
    for a,b,owner,gen in intervals:
        if b<=cursor:continue
        if a>cursor:break
        owners.add(owner);gens.add(gen);cursor=min(hi,b)
        if cursor==hi:
            label=next(iter(owners)) if len(owners)==1 else 'mixed_allocators' if 'unresolved' not in owners else 'unresolved'
            return label,sorted(gens)
    return 'unresolved',[]


def attribute(raw,race,calls,start,end):
    if end<start:raise ValueError('bad read clock')
    before=replay(calls,start);after=replay(calls,end);groups={};proof=[]
    for vma in mappings.parse_smaps(raw,race)['mappings']:
        lo,hi=vma['start'],vma['end'];label=vma['category']
        if label=='other_anonymous' and not vma['path']:
            a=cover(lo,hi,before);b=cover(lo,hi,after)
            unstable=any(c['start_ns']<=end and c['end_ns']>=start and any(x<hi and lo<z for x,z in affected(c)) for c in calls)
            label=a[0] if a==b and not unstable else 'unresolved'
            proof.append(dict(start=lo,end=hi,rss=vma['bytes']['Rss'],owner=label,generations=a[1] if a==b else [],read_overlaps_mutation=unstable))
        elif label=='other_anonymous':label=vma['path']
        groups[label]=groups.get(label,0)+vma['bytes']['Rss']
    return dict(groups_rss_bytes=groups,unnamed_vmas=proof)


LATE_TIMINGS={'checkpoint_seconds','snapshot_seconds'}


def point_core(point):return {k:v for k,v in point.items() if k not in LATE_TIMINGS}


def point_sha(point):return hashlib.sha256(json.dumps(point,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def validate_published_point(published,final):
    if point_core(published)!=point_core(final):raise ValueError('native resource/count/time core changed')
    for key in LATE_TIMINGS:
        a,b=published[key],final[key]
        if not all(type(x) in (float,int) and math.isfinite(x) and x>=0 for x in (a,b)) or (a!=0 and a!=b):raise ValueError('invalid late timing finalization')
    if final['snapshot_seconds']<final['measure_seconds']+final['checkpoint_seconds']:raise ValueError('incomplete final timing envelope')


class Collector:
    def __init__(self,folder,binary,control=False):
        self.folder=folder;self.binary=binary.resolve();self.control=control;self.records=[];self.seen=set();self.pid=None;self.start=None;self.verified=False
    def __call__(self):
        if self.pid is None:
            try:ident=context.proc_identity((self.folder/'target-before.stat').read_text())
            except (FileNotFoundError,ValueError,IndexError):return
            self.pid,self.start=ident['pid'],str(ident['start_ticks'])
        try:
            if mappings.pid_identity(self.pid)!=self.start:raise ValueError('PID reused')
            exe=Path(f'/proc/{self.pid}/exe').stat();expected=self.binary.stat()
            if (exe.st_dev,exe.st_ino)!=(expected.st_dev,expected.st_ino):return
            self.verified=True
            path=self.folder/'marker.json' if self.control else self.folder/'native/report.json'
            doc=json.loads(path.read_text())
        except (FileNotFoundError,ProcessLookupError,PermissionError):return
        if self.control:key=doc['phase'];point=doc
        else:
            if not doc['points']:return
            point=doc['points'][-1];key=(point['phase'],point['at_seconds'])
            if point['phase'] not in ('warmup','measured'):return
        if key in self.seen:return
        mtime=path.stat().st_mtime_ns;wall=time.time_ns();start=time.monotonic_ns();raw=Path(f'/proc/{self.pid}/smaps').read_text();end=time.monotonic_ns()
        newer=json.loads(path.read_text());same=newer if self.control else newer['points'][-1]
        if same!=point or mappings.pid_identity(self.pid)!=self.start:raise ValueError('checkpoint/PID changed while reading smaps')
        relative=f'mappings/{len(self.records):03d}.smaps.gz';target=self.folder/relative;target.parent.mkdir(exist_ok=True)
        with gzip.open(target,'wt') as f:f.write(raw)
        self.records.append(dict(key=key,point=point,file=relative,sha256=hashlib.sha256(target.read_bytes()).hexdigest(),published_point_sha256=point_sha(point),point_core_sha256=point_sha(point_core(point)),read_start_monotonic_ns=start,read_end_monotonic_ns=end,checkpoint_age_seconds=(wall-mtime)/1e9,pid=self.pid,start_ticks=self.start))
        context.dump(self.folder/'snapshots.json',dict(format_version=2,clock='CLOCK_MONOTONIC',binary_inode_verified=self.verified,records=self.records));self.seen.add(key)


def audit_snapshots(folder,ledger,race,control=False):
    capture=json.loads((folder/'snapshots.json').read_text());calls=prepare(ledger['calls']);out=[]
    if capture.get('format_version',1) not in (1,2):raise ValueError('unsupported snapshot format')
    execution=json.loads((folder/'execution.json').read_text())
    if capture['clock']!='CLOCK_MONOTONIC' or not capture['binary_inode_verified'] or not execution['target_identity_verified'] or not execution['group_gone']:raise ValueError('snapshot clock/executable/cleanup proof missing')
    for rec in capture['records']:
        if capture.get('format_version',1)==2 and (rec['published_point_sha256']!=point_sha(rec['point']) or rec['point_core_sha256']!=point_sha(point_core(rec['point']))):raise ValueError('published point hash mismatch')
        path=folder/rec['file']
        if hashlib.sha256(path.read_bytes()).hexdigest()!=rec['sha256'] or rec['pid']!=ledger['native_pid'] or rec['pid']!=execution['target_identity']['pid'] or rec['start_ticks']!=str(execution['target_identity']['start_ticks']):raise ValueError('snapshot identity/hash mismatch')
        start,end=rec['read_start_monotonic_ns'],rec['read_end_monotonic_ns']
        if start<ledger['target_exec_ns'] or end-start>100000000 or not 0<=rec['checkpoint_age_seconds']<=.1:raise ValueError('snapshot timing/clock failure')
        if control and start<rec['point']['monotonic_ns']:raise ValueError('control clock mismatch')
        out.append(dict(key=rec['key'],point=rec['point'],**attribute(gzip.open(path,'rt').read(),race,calls,start,end)))
    if control:
        if [x['key'] for x in out]!=['held','hole','reused','moved','released']:raise ValueError('missing control snapshots')
        for row in out:
            point=row['point'];base=point['base'];current=point['current'];state=replay(calls,next(r['read_start_monotonic_ns'] for r in capture['records'] if r['key']==row['key']))
            if row['key']=='held':assert cover(base,base+4*1024*1024,state)[0]=='trace_switch' and row['groups_rss_bytes'].get('trace_switch',0)>=4*1024*1024
            elif row['key']=='hole':assert not any(a<base+3*1024*1024 and base+1024*1024<b for a,b,_,_ in state) and not any(v['start']<base+3*1024*1024 and base+1024*1024<v['end'] for v in row['unnamed_vmas'])
            elif row['key']=='reused':assert cover(base+1024*1024,base+3*1024*1024,state)[0]=='internal_allocator' and row['groups_rss_bytes'].get('mixed_allocators',0)>=4*1024*1024
            elif row['key']=='moved':assert cover(current,current+8*1024*1024,state)[0]=='unresolved'
            elif row['key']=='released':assert cover(current,current+8*1024*1024,state)[0]=='unresolved' and not any(a<current+8*1024*1024 and current<b for a,b,_,_ in state)
    else:
        r=json.loads((folder/'native/report.json').read_text());wanted=[p for p in r['points'] if p['phase'] in ('warmup','measured')]
        if [x['key'] for x in out]!=[[p['phase'],p['at_seconds']] for p in wanted]:raise ValueError('missing native checkpoint mappings')
        for row,point in zip(out,wanted):validate_published_point(row['point'],point)
    return out


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--control',type=Path,required=True);p.add_argument('--tracer',type=Path,required=True);p.add_argument('--artifacts',type=Path,required=True);a=p.parse_args();a.artifacts.mkdir(parents=True,exist_ok=False)
    result={'status':'failed','pilot_only':True,'stages':[]}
    try:
        if os.sysconf('SC_PAGE_SIZE')!=PAGE:raise ValueError('only 4096-byte Linux pages supported')
        folder=a.artifacts/'control';collector=Collector(folder,a.control,True)
        ledger=context.launch(a.control,folder,CONTROL,[str(folder.resolve())],45,a.tracer,program_builder=program,auditor=parse,poll_hook=collector)
        rows=audit_snapshots(folder,ledger,False,True);result['control']=dict(ledger=ledger,snapshots=rows);result['stages'].append('control_passed')
        binary=a.binary.resolve();info=json.loads(subprocess.check_output([str(binary),'--describe']));assert mappings.supported(info)
        folder=a.artifacts/'pilot';collector=Collector(folder,binary);native=(folder/'native').resolve()
        ledger=context.launch(binary,folder,context.SYMBOLS,['--transport','3','--mode','1','--duration','15s','--warmup','12s','--sample-interval','5s','--workers','2','--qps','10','--pool-min','16','--pool-max','64','--artifacts',str(native)],120,a.tracer,program_builder=program,auditor=parse,poll_hook=collector)
        rows=audit_snapshots(folder,ledger,True);r=json.loads((native/'report.json').read_text());assert r['build_info']==info['build_info'] and r['settings']['pid']==ledger['native_pid']
        result['events']=verify.validate_events(native/'exchanges.jsonl.gz',r);verify.validate_engine_logs(native,folder/'native-stderr.log',64,3);result['acceptance']=verify.validate_report(r,True)
        result.update(status='pilot_passed',description=info,pilot=dict(ledger=ledger,snapshots=rows))
    except (ValueError,KeyError,OSError,AssertionError,subprocess.SubprocessError) as error:result['error']=type(error).__name__+': '+str(error)
    finally:context.dump(a.artifacts/'experiment.json',result)
    return int(result['status']!='pilot_passed')


if __name__=='__main__':raise SystemExit(main())
