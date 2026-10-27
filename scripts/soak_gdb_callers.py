#!/usr/bin/env python3
"""Run a bounded GDB caller experiment, then retain independent untraced acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import audit_soak_allocations as alloc
import soak_mappings as mappings
import verify_soak as verify

ROOT=Path(__file__).resolve().parent
SYMBOL='_ZN11__sanitizer13internal_mmapEPvmiiiy'


def dump(path,value):path.write_text(json.dumps(value,indent=2)+'\n')


def symbol_address(binary,symbol):
    header=subprocess.check_output(['readelf','-h',str(binary)],text=True)
    if not re.search(r'Type:\s+EXEC\b',header):raise ValueError('fixed entry address requires ET_EXEC')
    raw=subprocess.check_output(['nm','--defined-only',str(binary)],text=True)
    hits=[int(line.split()[0],16) for line in raw.splitlines() if line.split()[-1:]==[symbol]]
    if len(hits)!=1:raise ValueError('exact single entry symbol required')
    return hits[0],raw


def read_calls(folder):
    state=json.loads((folder/'gdb-result.json').read_text())
    entries={};returns={}
    for line in (folder/'mmap-calls.jsonl').read_text().splitlines():
        record=json.loads(line);key=record['id']
        target=entries if record['event']=='entry' else returns if record['event']=='return' else None
        if target is None or key in target:raise ValueError('unknown/duplicate GDB record')
        if target is returns and key not in entries:raise ValueError('return without entry')
        target[key]=record
    if len(entries)!=state['entry_calls'] or len(returns)!=state['returns'] or state['exit_code']!=0:
        raise ValueError('incomplete GDB execution')
    rows=[]
    for key,entry in entries.items():
        ret=returns.get(key)
        if ret and (ret['inferior_pid']!=entry['inferior_pid'] or ret['thread_ptid']!=entry['thread_ptid']):
            raise ValueError('return process/thread differs')
        # Linux internal_mmap returns unsigned -errno, not libc MAP_FAILED only.
        success=ret is not None and ret['rax'] < (1<<64)-4095
        rows.append(dict(id=key,size=entry['registers']['rsi'],address=ret['rax'] if success else None,
                         returned=ret is not None,successful=success,
                         caller_category=alloc.stack_owner([entry['backtrace']]),backtrace=entry['backtrace']))
    groups={}
    for row in rows:
        g=groups.setdefault(row['caller_category'],{'entries':0,'successful_returns':0,'cumulative_successful_virtual_bytes':0})
        g['entries']+=1
        if row['successful']:
            g['successful_returns']+=1;g['cumulative_successful_virtual_bytes']+=row['size']
    return {'gdb_state':state,'groups':groups,'rows':rows,
            'scope':'cumulative successful virtual requests, not live mappings or RSS; no unmap/reuse ledger; missing/unknown frames never guessed'}


def unwind_entry_covered(raw,address):
    ranges=[(int(a,16),int(b,16)) for a,b in re.findall(r'pc=([0-9a-f]+)\.\.([0-9a-f]+)',raw)]
    return any(start<=address<end for start,end in ranges)


def run_command(args,folder):
    return 'run '+shlex.join(args)+' >'+shlex.quote(str(folder/'native-stdout.log'))+' 2>'+shlex.quote(str(folder/'native-stderr.log'))+' < /dev/null'


def launch(binary,folder,symbol,args):
    folder.mkdir(parents=True,exist_ok=False)
    address,nm=symbol_address(binary,symbol)
    frames=subprocess.check_output(['readelf','--debug-dump=frames',str(binary)],text=True)
    (folder/'entry-unwind.txt').write_text(frames)
    if not unwind_entry_covered(frames,address):
        raise ValueError('GDB return probe blocked: no decoded FDE covers exact entry; do not use guessed FinishBreakpoint unwinding')
    dump(folder/'gdb-config.json',{'entry_symbol':symbol,'entry_address':address,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'inferior_arguments':args,'run_command':run_command(args,folder.resolve())})
    (folder/'binary-symbols.txt').write_text(nm)
    env=dict(os.environ);env['TUNVEO_GDB_OUTPUT']=str(folder.resolve())
    cmd=['gdb','--batch','--nx','-x',str(ROOT/'gdb_mmap.py'),'--args',str(binary),*args]
    with (folder/'gdb.log').open('w') as log:
        code=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=360).returncode
    result=read_calls(folder);result['gdb_exit_code']=code
    dump(folder/'caller-audit.json',result)
    if code:raise ValueError('GDB command failed')
    return result


def run(a):
    a.artifacts.mkdir(parents=True,exist_ok=False)
    binary=a.binary.resolve(strict=True);control=a.control.resolve(strict=True)
    info=json.loads(subprocess.check_output([str(binary),'--describe']))
    if not mappings.supported(info):raise ValueError('caller experiment requires Go1.26.10 Linux amd64 race')
    manifest={'description':info,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
              'pilot_only':True,'traced_duration_seconds':60,'untraced_duration_seconds':180,'errors':[]}
    dump(a.artifacts/'experiment.json',manifest)
    try:
        c=launch(control,a.artifacts/'control','control_mmap',[])
        values=json.loads((a.artifacts/'control/native-stdout.log').read_text())
        if len(c['rows'])!=1 or not c['rows'][0]['successful'] or c['rows'][0]['address']!=values['address'] or c['rows'][0]['size']!=values['size'] or values['size']!=1048576 or values['touched_pages']!=256 or values['checksum']!=1792 or not all(x in c['rows'][0]['backtrace'] for x in ('control_mmap','control_parent','main')):
            raise ValueError('known 1MiB allocation/caller control failed')
        manifest['control']='passed'
        native=(a.artifacts/'traced/native').resolve()
        result=launch(binary,a.artifacts/'traced',SYMBOL,['--transport','3','--mode','1','--duration','60s','--warmup','12s','--sample-interval','5s','--workers','2','--qps','10','--pool-min','16','--pool-max','64','--artifacts',str(native)])
        r=json.loads((native/'report.json').read_text())
        if r['build_info']!=info['build_info']:raise ValueError('traced build differs')
        manifest['traced_events']=verify.validate_events(native/'exchanges.jsonl.gz',r)
        verify.validate_engine_logs(native,a.artifacts/'traced/native-stderr.log',64,3)
        try:manifest['traced_acceptance']=verify.validate_report(r,True)
        except ValueError as error:
            manifest['traced_acceptance_error']=str(error)
            manifest['errors'].append('original traced resource/timing acceptance: '+str(error))
        manifest['caller_groups']=result['groups']
    except (ValueError,OSError,subprocess.SubprocessError) as error:
        manifest['errors'].append(type(error).__name__+': '+str(error))
    dump(a.artifacts/'experiment.json',manifest)
    # Independent original acceptance runs ONCE even when diagnostic collection failed.
    cmd=[sys.executable,str(ROOT/'soak_mappings.py'),'capture','--binary',str(binary),'--duration-seconds','180','--artifacts',str(a.artifacts/'untraced-180')]
    with (a.artifacts/'untraced-driver.log').open('w') as log:
        code=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=360).returncode
    manifest['untraced_exit_code']=code
    try:manifest['untraced_audit']=mappings.audit(a.artifacts/'untraced-180')
    except (ValueError,KeyError,OSError) as error:
        manifest['errors'].append('untraced audit: '+str(error))
    manifest['status']='failed' if code or manifest['errors'] else 'pilot_passed'
    manifest['scope']='GDB observer affects scheduling; caller evidence alone does not assign any prior 80MiB VMA or prove a leak; independent untraced pilot retains all original budgets'
    dump(a.artifacts/'experiment.json',manifest)
    return int(manifest['status']=='failed')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--control',type=Path,required=True);p.add_argument('--artifacts',type=Path,required=True)
    return run(p.parse_args())


if __name__=='__main__':raise SystemExit(main())
