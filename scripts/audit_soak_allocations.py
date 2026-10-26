#!/usr/bin/env python3
"""Conservative mmap-call-stack ownership. Never prorate VMA RSS by address span."""
import argparse
import gzip
import json
from decimal import Decimal
from pathlib import Path
import re
import soak_mappings as mappings

LINE = re.compile(r'^(\d+)\s+(\d+\.\d+)\s+(.*)$')


def ns(value):
    return int(Decimal(value)*10**9)


def stack_owner(stack):
    text='\n'.join(stack)
    if not ('__tsan' in text or '__sanitizer' in text):
        return 'unresolved'
    if any(x in text for x in ('TracePartAlloc', 'TraceSwitchPart', 'TraceAlloc')):
        return 'race_trace'
    if any(x in text for x in ('InternalAlloc', 'DenseSlabAlloc', 'StackDepot', 'ThreadRegistry')):
        return 'race_allocator_other'
    return 'race_runtime_other'


def parse_trace(raw):
    events=[];pending={};last=None
    for line in raw.splitlines():
        if line.lstrip().startswith('>'):
            if last is not None:last['stack'].append(line.strip())
            continue
        match=LINE.match(line)
        if not match:continue
        tid,stamp,body=int(match[1]),ns(match[2]),match[3]
        if '<unfinished ...>' in body:
            pending[tid]=(stamp,body.split('<unfinished ...>')[0]);last=None;continue
        resumed=re.match(r'<\.\.\. (\w+) resumed>(.*)',body)
        if resumed:
            if tid not in pending:raise ValueError('resumed syscall without beginning')
            stamp,prefix=pending.pop(tid);body=prefix+resumed[2]
        call=re.match(r'(\w+)\(',body)
        if not call: last=None;continue
        duration=re.search(r'<([0-9.]+)>$',body)
        if duration is None:raise ValueError('syscall duration missing')
        last=dict(tid=tid,at_ns=stamp+ns(duration[1]),call=call[1],body=body,stack=[])
        events.append(last)
    if pending:raise ValueError('unfinished syscalls at trace end')
    return sorted(events,key=lambda e:e['at_ns'])


def native_events(events,pid):
    tids={pid};selected=[]
    # Parent's completed clone may print after a child starts using the mapping;
    # establish the process subtree before chronological replay.
    changed=True
    while changed:
        changed=False
        for e in events:
            if e['tid'] in tids and e['call'] in ('clone','clone3','fork','vfork'):
                child=re.search(r'= (\d+)\s+<',e['body'])
                if child and int(child[1]) not in tids:tids.add(int(child[1]));changed=True
    for e in events:
        if e['tid'] in tids:selected.append(e)
    return selected


def remove(intervals,lo,hi):
    result=[]
    for start,end,owner in intervals:
        if end<=lo or start>=hi:result.append((start,end,owner));continue
        if start<lo:result.append((start,lo,owner))
        if end>hi:result.append((hi,end,owner))
    return result


def allocations_at(events,at):
    intervals=[]
    for e in events:
        if e['at_ns']>at:break
        body=e['body'];ret=re.search(r'= (0x[0-9a-f]+|0|-1)\b',body)
        if ret is None:continue
        if ret[1]=='-1':continue
        if e['call']=='mmap':
            size=re.match(r'mmap\([^,]+,\s*(\d+)\s*,',body)
            if size is None or not ret[1].startswith('0x'):raise ValueError('unparsed mmap')
            start=int(ret[1],16);end=start+int(size[1]);intervals=remove(intervals,start,end)
            intervals.append((start,end,stack_owner(e['stack'])))
        elif e['call']=='munmap':
            args=re.match(r'munmap\((0x[0-9a-f]+),\s*(\d+)\s*\)',body)
            if args is None:raise ValueError('unparsed munmap')
            lo=int(args[1],16);intervals=remove(intervals,lo,lo+int(args[2]))
        elif e['call']=='mremap':
            args=re.match(r'mremap\((0x[0-9a-f]+),\s*(\d+)\s*,\s*(\d+)\s*,',body)
            if args is None or not ret[1].startswith('0x'):raise ValueError('unparsed mremap')
            lo=int(args[1],16);intervals=remove(intervals,lo,lo+int(args[2]))
            lo=int(ret[1],16);end=lo+int(args[3]);intervals=remove(intervals,lo,end)
            intervals.append((lo,end,'unresolved'))
    return sorted(intervals)


def owner_of(vma,intervals):
    cursor=vma['start'];owners=set()
    for lo,hi,owner in intervals:
        if hi<=cursor:continue
        if lo>cursor:break
        owners.add(owner);cursor=min(hi,vma['end'])
        if cursor==vma['end']:
            if len(owners)==1:return next(iter(owners))
            if all(x.startswith('race_') for x in owners):return 'race_runtime_mixed'
            return 'unresolved'
    return 'unresolved'


def classify_snapshot(folder,point,events,race):
    import hashlib
    path=folder/point['file']
    if hashlib.sha256(path.read_bytes()).hexdigest()!=point['sha256']:raise ValueError('smaps hash mismatch')
    vmas=mappings.parse_smaps(gzip.open(path,'rt').read(),race)['mappings']
    before=allocations_at(events,point['read_started_ns']);after=allocations_at(events,point['read_finished_ns'])
    groups={};proof=[]
    for vma in vmas:
        if vma['category']=='other_anonymous' and not vma['path']:
            start_owner=owner_of(vma,before);end_owner=owner_of(vma,after)
            owner=start_owner if start_owner==end_owner else 'unresolved'
            proof.append(dict(start=hex(vma['start']),end=hex(vma['end']),rss=vma['bytes']['Rss'],owner=owner))
        elif vma['category']=='other_anonymous':owner=vma['path']
        else:owner=vma['category']
        groups[owner]=groups.get(owner,0)+vma['bytes']['Rss']
    return dict(groups=groups,unnamed_vmas=proof)


def audit(folder,trace,control=False):
    raw=trace.read_text(errors='strict');all_events=parse_trace(raw)
    if control:
        report=json.loads((folder/'control.json').read_text());pid=report['native_pid'];points=[r['snapshot'] for r in report['rows']];race=report['race']
    else:
        report=json.loads((folder/'mapping-report.json').read_text());pid=report['native_pid'];points=report['samples'];race=report['race']
    events=native_events(all_events,pid)
    mmaps=[e for e in events if e['call']=='mmap' and '= -1' not in e['body']]
    if not mmaps or not any(e['stack'] for e in mmaps):raise ValueError('no native mmap call stacks')
    rows=[]
    for point in points:
        rows.append(dict(at_seconds=point.get('at_seconds'),phase=point.get('phase'),
                         **classify_snapshot(folder,point,events,race)))
    import hashlib
    return dict(trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),native_pid=pid,
                native_mmaps=len(mmaps),native_mmaps_with_stacks=sum(bool(e['stack']) for e in mmaps),
                mmap_owners={owner:sum(stack_owner(e['stack'])==owner for e in mmaps)
                             for owner in sorted({stack_owner(e['stack']) for e in mmaps})},
                rows=rows,scope='complete VMA coverage by live mmap intervals at both read boundaries; mixed/partial/unwound frames remain unresolved; adjacent snapshots not atomic')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('artifacts',type=Path);p.add_argument('--trace',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--control',action='store_true');a=p.parse_args()
    result=audit(a.artifacts,a.trace,a.control);a.output.write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
