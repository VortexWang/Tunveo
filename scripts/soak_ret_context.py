#!/usr/bin/env python3
"""Exact entry/RET-site uprobes: qualification only, never resident attribution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
import verify_soak as verify
import soak_mappings as mappings

SYMBOLS={1:'_ZN6__tsan19TraceSwitchPartImplEPNS_11ThreadStateE',
         2:'_ZN11__sanitizer13InternalAllocEmPNS_30SizeClassAllocator32LocalCacheINS_20SizeClassAllocator32INS_4AP32EEEEEm',
         3:'_ZN11__sanitizer13internal_mmapEPvmiiiy'}


def dump(path,value):path.write_text(json.dumps(value,indent=2)+'\n')


def ret_sites(raw,start,size):
    rows=[]
    for line in raw.splitlines():
        parts=line.split('\t')
        if len(parts)<3 or not re.fullmatch(r'\s*[0-9a-f]+:\s*',parts[0]):continue
        address=int(parts[0].strip()[:-1],16)
        if not start<=address<start+size:continue
        data=bytes.fromhex(parts[1]);asm=parts[2].strip()
        if not data:raise ValueError('empty instruction')
        rows.append((address,data,asm))
    cursor=start;sites=[]
    for address,data,asm in rows:
        if address!=cursor:raise ValueError('incomplete or overlapping function disassembly')
        cursor+=len(data)
        if asm.split()[0] in ('ret','retq'):
            if data!=b'\xc3':raise ValueError('unsupported RET encoding')
            sites.append(address-start)
    if cursor!=start+size or not sites:raise ValueError('complete symbol and at least one plain RET required')
    return sites


def tail_sites(raw,start,size,allowed):
    exits=[]
    for line in raw.splitlines():
        parts=line.split('\t')
        if len(parts)<3 or not re.fullmatch(r'\s*[0-9a-f]+:\s*',parts[0]):continue
        address=int(parts[0].strip()[:-1],16)
        if not start<=address<start+size:continue
        asm=parts[2].strip();match=re.match(r'(j[a-z]+)\s+([0-9a-f]+)\b',asm)
        if asm.startswith('jmp') and not match:raise ValueError('unsupported indirect tail exit')
        if match and not start<=int(match[2],16)<start+size:
            target=int(match[2],16)
            if match[1]!='jmp' or target not in allowed:raise ValueError('unplanned function-range exit')
            exits.append(dict(offset=address-start,target=target,symbol=allowed[target]))
    return exits


def plan(binary,symbols):
    header=subprocess.check_output(['readelf','-h',str(binary)],text=True)
    if not re.search(r'Type:\s+EXEC\b',header):raise ValueError('ET_EXEC required')
    nm=subprocess.check_output(['nm','-S','--defined-only',str(binary)],text=True)
    functions={}
    slot='_ZN6__tsan10SlotUnlockEPNS_11ThreadStateE'
    slot_lines=[x.split() for x in nm.splitlines() if x.split()[-1:]==[slot]]
    for kind,symbol in symbols.items():
        lines=[x.split() for x in nm.splitlines() if x.split()[-1:]==[symbol]]
        if len(lines)!=1 or len(lines[0])!=4:raise ValueError('unique sized symbol required')
        start,size=int(lines[0][0],16),int(lines[0][1],16)
        raw=subprocess.check_output(['objdump','-dz','--insn-width=16','--disassemble='+symbol,str(binary)],text=True)
        functions[str(kind)]={'symbol':symbol,'address':start,'size':size,'ret_offsets':ret_sites(raw,start,size),'tail_exits':tail_sites(raw,start,size,{int(slot_lines[0][0],16):slot} if kind==1 and len(slot_lines)==1 else {}),'disassembly':raw}
    return {'binary':str(binary),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'functions':functions}


def program(p):
    # Only ordinary uprobes; no uretprobe, return-address replacement or stack walk.
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+',p['binary']):raise ValueError('unsupported tracer path literal')
    lines=['BEGIN { printf("{\\"event\\":\\"begin\\",\\"pid\\":%d}\\n", cpid); }']
    for kind,f in p['functions'].items():
        for event,offset in [('entry',0)]+[('ret',x) for x in f['ret_offsets']]+[('tail_exit',x['offset']) for x in f.get('tail_exits',[])]:
            site=f['address']+offset
            size='arg1' if event=='entry' and kind=='3' else '0'
            value='reg("ax")' if event=='ret' else '0'
            fmt='{"event":"%s","kind":%s,"site":%s,"pid":%%d,"tid":%%d,"uid":%%d,"seq":%%llu,"ns":%%llu,"sp":%%llu,"size":%%llu,"value":%%llu}\\n'%(event,kind,site)
            quoted=fmt.replace('"','\\"')
            lines.append('uprobe:%s:%s+0x%x /pid == cpid/ { @seq[tid] = @seq[tid] + 1; printf("%s", pid, tid, uid, @seq[tid], nsecs, reg("sp"), %s, %s); }'%(p['binary'],f['symbol'],offset,quoted,size,value))
    lines.append('END { printf("{\\"event\\":\\"end\\",\\"pid\\":%d}\\n", cpid); }')
    return '\n'.join(lines)+'\n'


def audit_events(raw,p,expected_uid):
    records=[];ledger={};begin=[];end=[]
    for line in raw.splitlines():
        if not line.strip():continue
        match=re.fullmatch(r'@seq\[(\d+)\]: (\d+)',line)
        if match:
            tid,count=map(int,match.groups())
            if tid in ledger:raise ValueError('duplicate thread ledger')
            ledger[tid]=count;continue
        r=json.loads(line)
        if r['event']=='begin':begin.append(r);continue
        if r['event']=='end':end.append(r);continue
        if r['event'] not in ('entry','ret','tail_exit'):raise ValueError('unknown event')
        records.append(r)
    if len(begin)!=1 or len(end)!=1 or begin[0]['pid']<=0 or begin[0]!=dict(event='begin',pid=end[0]['pid']):raise ValueError('incomplete begin/end')
    pid=begin[0]['pid'];threads={}
    for r in records:
        f=p['functions'][str(r['kind'])]
        if r['pid']!=pid or r['uid']!=expected_uid:raise ValueError('target PID/UID mismatch')
        allowed=[f['address']] if r['event']=='entry' else [f['address']+n for n in f['ret_offsets']] if r['event']=='ret' else [f['address']+n['offset'] for n in f.get('tail_exits',[])]
        if r['site'] not in allowed:raise ValueError('event at unplanned instruction')
        threads.setdefault(r['tid'],[]).append(r)
    if set(threads)!=set(ledger) or not threads:raise ValueError('missing entire thread or empty capture')
    maps=[];counts={};tail_counts={}
    for tid,rows in threads.items():
        rows.sort(key=lambda r:r['seq']);stack=[];previous=-1
        if [r['seq'] for r in rows]!=list(range(1,ledger[tid]+1)):raise ValueError('missing/duplicate per-thread events')
        for r in rows:
            if r['ns']<previous:raise ValueError('backward event clock')
            previous=r['ns']
            if r['event']=='entry':
                if stack and r['sp']>stack[-1]['sp']:raise ValueError('non-nested C ABI stack')
                stack.append(r)
            else:
                if not stack:raise ValueError('RET without entry')
                entry=stack.pop()
                if (entry['kind'],entry['sp'])!=(r['kind'],r['sp']):raise ValueError('RET kind/SP does not match innermost entry')
                counts[str(r['kind'])]=counts.get(str(r['kind']),0)+1
                if r['event']=='tail_exit':tail_counts[str(r['kind'])]=tail_counts.get(str(r['kind']),0)+1
                if r['kind']==3:
                    contexts=[e['kind'] for e in stack]
                    maps.append({'tid':tid,'entry_seq':entry['seq'],'return_seq':r['seq'],'size':entry['size'],'value':r['value'],'successful':r['value']<(1<<64)-4095,'observed_contexts':contexts})
        if stack:raise ValueError('unclosed contexts at process end')
    return {'native_pid':pid,'events':len(records),'thread_ledger':ledger,'matched_pairs_by_kind':counts,'matched_tail_exits_by_kind':tail_counts,'mmap_calls':maps,'scope':'completed exact entry/RET or whitelisted direct lexical tail-exit observations in one C ABI thread stack; cumulative virtual requests only; no full mmap/unmap ledger or RSS ownership'}


def group_alive(pgid):
    result=subprocess.run(['sudo','-n','kill','-0','--','-'+str(pgid)],capture_output=True,text=True)
    if result.returncode==0:return True
    if 'No such process' in result.stderr:return False
    raise ValueError('cannot prove process-group state: '+result.stderr[:200])


def bpf_child_command(launcher):
    path=str(launcher.resolve())
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+',path):raise ValueError('unsupported child-script path')
    return '/bin/sh '+path


def proc_identity(raw):
    pid=int(raw.split(' ',1)[0]);fields=raw.rsplit(')',1)[1].split()
    return dict(pid=pid,ppid=int(fields[1]),pgid=int(fields[2]),session=int(fields[3]),start_ticks=int(fields[19]))


def owned_groups(group,target,parent,parent_exe,tracer):
    if target['ppid']!=parent['pid'] or target['session']!=parent['session'] or parent['session'] not in (group,parent['pid']) or parent_exe.strip()!=str(tracer):
        raise ValueError('unverified tracer/target process lineage')
    groups={group,target['pgid'],parent['pgid']}
    if not groups<={group,target['pid'],parent['pid']}:raise ValueError('unknown descendant process group')
    return sorted(groups)


def launch(binary,folder,symbols,args,seconds,tracer=Path('/usr/bin/bpftrace'),*,program_builder=None,auditor=None,poll_hook=None):
    folder.mkdir(parents=True,exist_ok=False);binary=binary.resolve(strict=True)
    tracer=tracer.resolve(strict=True)
    p=plan(binary,symbols);dump(folder/'plan.json',p);(folder/'program.bt').write_text((program_builder or program)(p))
    command='exec '+shlex.join(['setpriv','--reuid='+str(os.getuid()),'--regid='+str(os.getgid()),'--clear-groups','env','-i','PATH=/usr/bin:/bin',str(binary),*args])+' >'+shlex.quote(str((folder/'native-stdout.log').resolve()))+' 2>'+shlex.quote(str((folder/'native-stderr.log').resolve()))
    launcher=folder/'target.sh'
    launcher.write_text('#!/bin/sh\nset -eu\ncat /proc/$$/stat >'+shlex.quote(str((folder/'target-before.stat').resolve()))+'\ncat /proc/$PPID/stat >'+shlex.quote(str((folder/'tracer-before.stat').resolve()))+'\nreadlink /proc/$PPID/exe >'+shlex.quote(str((folder/'tracer-exe.txt').resolve()))+'\n'+command+'\n')
    cmd=['sudo','-n',str(tracer),'-q',str((folder/'program.bt').resolve()),'-c',bpf_child_command(launcher)]
    execution={'command':cmd,'expected_uid':os.getuid(),'timeout_seconds':seconds,'timed_out':False,'cleanup_signals':[]}
    with (folder/'events.log').open('w') as out,(folder/'bpftrace-stderr.log').open('w') as err:
        proc=subprocess.Popen(cmd,stdout=out,stderr=err,start_new_session=True)
        execution['process_group']=proc.pid
        try:
            if poll_hook is None:execution['exit_code']=proc.wait(timeout=seconds)
            else:
                deadline=time.monotonic()+seconds
                while proc.poll() is None:
                    poll_hook()
                    if time.monotonic()>=deadline:raise subprocess.TimeoutExpired(cmd,seconds)
                    try:proc.wait(timeout=.02)
                    except subprocess.TimeoutExpired:pass
                execution['exit_code']=proc.returncode
        except subprocess.TimeoutExpired:execution['timed_out']=True
        finally:
            groups=[proc.pid]
            try:
                target=proc_identity((folder/'target-before.stat').read_text())
                parent=proc_identity((folder/'tracer-before.stat').read_text())
                groups=owned_groups(proc.pid,target,parent,(folder/'tracer-exe.txt').read_text(),tracer)
                execution.update(target_identity=target,tracer_identity=parent,target_identity_verified=True)
            except (OSError,ValueError,IndexError) as error:
                execution.update(target_identity_verified=False,identity_error=str(error))
            execution['owned_groups']=groups
            try:
                for sig in ('TERM','KILL'):
                    alive=[g for g in groups if group_alive(g)]
                    if not alive:break
                    for group in alive:
                        subprocess.run(['sudo','-n','kill','-'+sig,'--','-'+str(group)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    execution['cleanup_signals'].append(sig)
                    until=time.monotonic()+5
                    while any(group_alive(g) for g in groups) and time.monotonic()<until:time.sleep(.1)
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:pass
                execution['group_gone']=not any(group_alive(g) for g in groups)
            except ValueError as error:
                execution.update(group_gone=False,cleanup_error=str(error))
            dump(folder/'execution.json',execution)
    if execution['timed_out'] or execution.get('exit_code')!=0 or not execution['group_gone'] or execution['cleanup_signals'] or not execution['target_identity_verified']:
        raise ValueError('tracer/target did not complete cleanly; later stages blocked')
    stderr=(folder/'bpftrace-stderr.log').read_text()
    if re.search(r'(?i)lost|dropped|error|failed',stderr):raise ValueError('tracer reports loss or failure')
    result=(auditor or audit_events)((folder/'events.log').read_text(),p,os.getuid());dump(folder/'context-audit.json',result)
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--binary',type=Path,required=True);ap.add_argument('--control',type=Path,required=True);ap.add_argument('--artifacts',type=Path,required=True);ap.add_argument('--tracer',type=Path,default=Path('/usr/bin/bpftrace'));a=ap.parse_args()
    a.artifacts.mkdir(parents=True,exist_ok=False);manifest={'pilot_only':True,'qualification_seconds':15,'status':'failed','stages':[]}
    try:
        c=launch(a.control,a.artifacts/'control',{1:'control_parent',3:'control_mmap'},[],45,a.tracer)
        expected=json.loads((a.artifacts/'control/native-stdout.log').read_text());calls=c['mmap_calls']
        if len(calls)!=1 or calls[0]['observed_contexts']!=[1] or not calls[0]['successful'] or calls[0]['size']!=1048576 or calls[0]['value']!=expected['address'] or expected['checksum']!=1792 or expected['touched_pages']!=256:
            raise ValueError('known context/address/touched-allocation control failed')
        manifest['stages'].append('control_passed')
        binary=a.binary.resolve(strict=True);info=json.loads(subprocess.check_output([str(binary),'--describe']))
        if not mappings.supported(info):raise ValueError('Go1.26.10 linux/amd64 race required')
        manifest['description']=info
        native=(a.artifacts/'qualification/native').resolve()
        r=launch(binary,a.artifacts/'qualification',SYMBOLS,['--transport','3','--mode','1','--duration','15s','--warmup','12s','--sample-interval','5s','--workers','2','--qps','10','--pool-min','16','--pool-max','64','--artifacts',str(native)],120,a.tracer)
        report=json.loads((native/'report.json').read_text())
        if report['build_info']!=info['build_info'] or report['settings']['pid']!=r['native_pid']:raise ValueError('native identity/build mismatch')
        manifest['audited_events']=verify.validate_events(native/'exchanges.jsonl.gz',report)
        verify.validate_engine_logs(native,a.artifacts/'qualification/native-stderr.log',64,3)
        manifest['acceptance']=verify.validate_report(report,True)
        manifest['context_audit']=r;manifest['status']='pilot_passed'
    except (ValueError,KeyError,OSError,subprocess.SubprocessError) as error:manifest['error']=type(error).__name__+': '+str(error)
    finally:dump(a.artifacts/'experiment.json',manifest)
    return int(manifest['status']!='pilot_passed')


if __name__=='__main__':raise SystemExit(main())
