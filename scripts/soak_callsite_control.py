#!/usr/bin/env python3
"""Direct CALL/next-instruction control on a byte-pinned PR35 ELF; no RSS ownership."""
import argparse,hashlib,json,re,struct,subprocess,zipfile
from pathlib import Path
import soak_ret_context as context
import verify_soak as verify

ARCHIVE_SHA='3722365efe2bf1f7f7378e2bae89fe5c3ad00ddb065449440e01208d746d63ce'
BINARY_SHA='2b332b9b27afeecca123e2d3fb5819c31bd787406d1393b1335e649a78eec391'
OWNER='_ZN6__tsan19TraceSwitchPartImplEPNS_11ThreadStateE'
CALLEE='_ZN11__sanitizer9MmapOrDieEmPKcb'
REVISION='b362c900b25935f39b3b8b271fc8664c4bde9a3c'

def dump(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def sha(b):return hashlib.sha256(b).hexdigest()

def extract(archive,destination):
    if sha(archive.read_bytes())!=ARCHIVE_SHA:raise ValueError('frozen archive digest mismatch')
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None or len(z.namelist())!=len(set(z.namelist())):raise ValueError('archive CRC/duplicate failure')
        data=z.read('binaries/probe')
    if sha(data)!=BINARY_SHA:raise ValueError('frozen ELF digest mismatch')
    destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(data);destination.chmod(0o755)

def file_offset(binary,address,length=1):
    data=binary.read_bytes()
    if data[:6]!=b'\x7fELF\x02\x01':raise ValueError('ELF64 little endian required')
    kind,machine=struct.unpack_from('<HH',data,16)
    if (kind,machine)!=(2,62):raise ValueError('x86_64 ET_EXEC required')
    phoff=struct.unpack_from('<Q',data,32)[0];entsize,count=struct.unpack_from('<HH',data,54)
    matches=[]
    for i in range(count):
        typ,flags,off,vaddr,_,filesz,_,_=struct.unpack_from('<IIQQQQQQ',data,phoff+i*entsize)
        if typ==1 and flags&1 and vaddr<=address and address+length<=vaddr+filesz:matches.append(off+address-vaddr)
    if len(matches)!=1:raise ValueError('unique executable file-backed segment required')
    return matches[0]

def call_site(p):
    f=p['functions']['1'];target=CALLEE if f['symbol']==OWNER else 'control_map'
    instructions=[]
    for line in f['disassembly'].splitlines():
        parts=line.split('\t')
        if len(parts)>=3 and re.fullmatch(r'\s*[0-9a-f]+:\s*',parts[0]):
            address=int(parts[0].strip()[:-1],16)
            if f['address']<=address<f['address']+f['size']:instructions.append((address,bytes.fromhex(parts[1]),parts[2].strip()))
    hits=[]
    for i,(address,data,asm) in enumerate(instructions):
        if re.fullmatch(r'call[q]?\s+[0-9a-f]+\s+<'+re.escape(target)+r'>',asm):
            if len(data)!=5 or data[0]!=0xe8 or i+1==len(instructions) or instructions[i+1][0]!=address+5:raise ValueError('direct CALL and next instruction required')
            destination=address+5+struct.unpack('<i',data[1:])[0]
            if destination!=int(asm.split()[1],16):raise ValueError('relative call destination mismatch')
            binary=Path(p['binary']);offset=file_offset(binary,address,5);post_offset=file_offset(binary,address+5,len(instructions[i+1][1]));raw=binary.read_bytes()
            if raw[offset:offset+5]!=data or raw[post_offset:post_offset+len(instructions[i+1][1])]!=instructions[i+1][1]:raise ValueError('instruction/ELF byte mismatch')
            hits.append({'call':address,'after':address+5,'callee':destination,'call_file_offset':offset,'after_file_offset':post_offset,'call_hex':data.hex(),'after_hex':instructions[i+1][1].hex(),'callee_symbol':target})
    if len(hits)!=1:raise ValueError('exactly one candidate call required')
    if f['symbol']==OWNER:
        if p['binary_sha256']!=BINARY_SHA or (hits[0]['call'],hits[0]['after'],hits[0]['callee'])!=(0x41d8fc,0x41d901,0x40df10):raise ValueError('frozen site mismatch')
        # This read-only segment is deliberately separate from executable offsets.
        raw=Path(p['binary']).read_bytes()
        if raw[0xd29cef-0x400000:0xd29cef-0x400000+10]!=b'TracePart\0':raise ValueError('frozen tag mismatch')
    return hits[0]

def program(p):
    site=call_site(p);binary=p['binary']
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+',binary):raise ValueError('unsupported path')
    lines=['BEGIN { printf("{\\"event\\":\\"begin\\",\\"pid\\":%d}\\n", cpid); }']
    probes=[('call',f'uprobe:{binary}:0x{site["call"]:x}','reg("di")','0','reg("si")','reg("dx")',site['call']),('after',f'uprobe:{binary}:0x{site["after"]:x}','0','reg("ax")','0','0',site['after']),('mmap_entry','tracepoint:syscalls:sys_enter_mmap','args.len','args.addr','args.flags','args.prot',0),('mmap_exit','tracepoint:syscalls:sys_exit_mmap','0','(uint64)args.ret','0','0',0)]
    for event,probe,size,value,tag,flags,addr in probes:
        fmt=json.dumps({'event':event,'site':addr})[:-1]+',"pid":%d,"tid":%d,"uid":%d,"seq":%llu,"ns":%llu,"sp":%llu,"size":%llu,"value":%llu,"tag":%llu,"flags":%llu}\\n'
        quoted=fmt.replace('"','\\"')
        sp='reg("sp")' if event in ('call','after') else '0'
        lines.append(f'{probe} /pid == cpid/ {{ @seq[tid] = @seq[tid] + 1; printf("{quoted}",pid,tid,uid,@seq[tid],nsecs,{sp},{size},{value},{tag},{flags}); }}')
    lines.append('END { printf("{\\"event\\":\\"end\\",\\"pid\\":%d}\\n", cpid); }')
    return '\n'.join(lines)+'\n'

def audit(raw,p,uid):
    site=call_site(p);records=[];ledger={};beg=[];end=[]
    for line in raw.splitlines():
        if not line.strip():continue
        m=re.fullmatch(r'@seq\[(\d+)\]: (\d+)',line)
        if m:
            tid,n=map(int,m.groups())
            if tid in ledger:raise ValueError('duplicate ledger')
            ledger[tid]=n;continue
        r=json.loads(line)
        if r['event']=='begin':beg.append(r)
        elif r['event']=='end':end.append(r)
        elif r['event'] in ('call','after','mmap_entry','mmap_exit'):records.append(r)
        else:raise ValueError('unknown event')
    if len(beg)!=1 or len(end)!=1 or beg[0]['pid']<=0 or beg[0]['pid']!=end[0]['pid']:raise ValueError('incomplete begin/end')
    pid=beg[0]['pid'];threads={};calls=[];syscalls=0
    for r in records:
        if r['pid']!=pid or r['uid']!=uid:raise ValueError('PID/UID mismatch')
        if r['site']!=({'call':site['call'],'after':site['after']}.get(r['event'],0)):raise ValueError('unplanned site')
        threads.setdefault(r['tid'],[]).append(r)
    if not threads or set(threads)!=set(ledger):raise ValueError('missing thread or empty capture')
    for tid,rows in threads.items():
        rows.sort(key=lambda r:r['seq']);stack=[];pending=None;last=-1
        if [r['seq'] for r in rows]!=list(range(1,ledger[tid]+1)):raise ValueError('missing/duplicate event')
        for r in rows:
            if r['ns']<last:raise ValueError('backward clock')
            last=r['ns'];event=r['event']
            if event=='call':
                if pending is not None or (stack and r['sp']>=stack[-1]['entry']['sp']):raise ValueError('unsupported nesting')
                stack.append({'entry':r,'maps':[]})
            elif event=='mmap_entry':
                if pending is not None:raise ValueError('nested or missing mmap exit')
                pending=(r,len(stack))
            elif event=='mmap_exit':
                if pending is None or pending[1]!=len(stack):raise ValueError('mmap exit without matching entry/context')
                entry,_=pending;pending=None;syscalls+=1
                if stack:stack[-1]['maps'].append({'entry':entry,'exit':r})
            else:
                if not stack or pending is not None:raise ValueError('unpaired call completion')
                frame=stack.pop();entry=frame['entry']
                if entry['sp']!=r['sp']:raise ValueError('CALL/after stack pointer mismatch')
                if len(frame['maps'])!=1:raise ValueError('exactly one mmap per observed direct call required')
                m=frame['maps'][0]
                if not 0<r['value']<(1<<64)-4095 or r['value']%4096 or r['value']!=m['exit']['value'] or entry['size']!=m['entry']['size']:raise ValueError('size/return/syscall mismatch')
                if site['callee_symbol']==CALLEE and (entry['size'],entry['tag'],entry['flags'])!=(131072,0xd29cef,0):raise ValueError('frozen TracePart arguments mismatch')
                calls.append({'tid':tid,'call_seq':entry['seq'],'after_seq':r['seq'],'size':entry['size'],'pointer':r['value'],'mmap_entry_seq':m['entry']['seq'],'mmap_exit_seq':m['exit']['seq']})
        if stack or pending is not None:raise ValueError('unclosed call/syscall at end')
    if not calls:raise ValueError('candidate path not observed')
    return {'native_pid':pid,'site':site,'events':len(records),'thread_ledger':ledger,'mmap_syscalls':syscalls,'calls':calls,'scope':'completed direct call and its mmap only; no free/unmap generations, whole-runtime coverage, RSS ownership or acceptance'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('binary','control','tracer','artifacts'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();a.artifacts.mkdir(parents=True,exist_ok=False);result={'status':'failed','qualifies_24h':False,'historical_rss_failures_retained':True,'rss_budget':67108864,'stages':[]}
    try:
        if sha(a.binary.read_bytes())!=BINARY_SHA:raise ValueError('only PR35 frozen ELF accepted')
        c=context.launch(a.control,a.artifacts/'control',{1:'control_site'},[],60,a.tracer,program_builder=program,auditor=audit)
        expected=[json.loads(l) for l in (a.artifacts/'control/native-stdout.log').read_text().splitlines()]
        key=lambda r:(r['tid'],r['size'],r['pointer'])
        if len(expected)!=32 or len({r['tid'] for r in expected})!=4 or sorted(map(key,expected))!=sorted(map(key,c['calls'])) or sorted(r['size'] for r in expected)!=[i*4096 for i in range(1,33)]:raise ValueError('known multithread control mismatch')
        result['control']=c;result['stages'].append('known_control_passed')
        info=json.loads(subprocess.check_output([str(a.binary.resolve()),'--describe'],text=True))
        if 'vcs.revision='+REVISION not in info['build_info'] or 'vcs.modified=false' not in info['build_info']:raise ValueError('frozen build identity mismatch')
        result['description']=info;native=(a.artifacts/'qualification/native').resolve()
        r=context.launch(a.binary,a.artifacts/'qualification',{1:OWNER},['--transport','3','--mode','1','--duration','15s','--warmup','12s','--sample-interval','5s','--workers','2','--qps','10','--pool-min','16','--pool-max','64','--artifacts',str(native)],120,a.tracer,program_builder=program,auditor=audit)
        result['call_control']=r;result['stages'].append('actual_call_control_passed')
        report=json.loads((native/'report.json').read_text())
        if report['build_info']!=info['build_info'] or report['settings']['pid']!=r['native_pid']:raise ValueError('native report identity mismatch')
        result['business_events']=verify.validate_events(native/'exchanges.jsonl.gz',report)
        verify.validate_engine_logs(native,a.artifacts/'qualification/native-stderr.log',64,3)
        result['pilot_resources']=verify.validate_report(report,True);result['status']='call_control_passed'
    except (ValueError,KeyError,OSError,subprocess.SubprocessError) as e:result['error']=type(e).__name__+': '+str(e)
    finally:
        result['files']={str(f.relative_to(a.artifacts)):sha(f.read_bytes()) for f in a.artifacts.rglob('*') if f.is_file() and f.name!='experiment.json'}
        dump(a.artifacts/'experiment.json',result)
    return int(result['status']!='call_control_passed')
if __name__=='__main__':raise SystemExit(main())
