#!/usr/bin/env python3
"""Status-bit-only pagemap observation; present-page counts are not smaps RSS."""
import argparse,array,bisect,gzip,json,os,struct,subprocess,sys,time
from collections import Counter
from pathlib import Path
import soak_call_lifecycle as life
import soak_mapping_retention as retention
import soak_mapping_ledger as old
import soak_callsite_control as callsite
PAGE=4096
MAX_BYTES=1024*1024*1024
MAX_CAPTURE_NS=250000000
PHASES=['untouched','read_zero','held','discarded','failed_advice','retouched','hole','reused','moved','released']

def atomic(path,value):
    tmp=path.with_suffix('.tmp');callsite.dump(tmp,value);tmp.replace(path)
def selected(raw):
    return [v for v in life.mappings.parse_smaps(raw,True)['mappings'] if not v['path'] and v['category']=='other_anonymous' and v['permissions'][0]=='r']
def signature(v):return (v['start'],v['end'],v['permissions'],v['path'])
def encode_flags(raw):
    if len(raw)%8:raise ValueError('short/unaligned pagemap read')
    flags=array.array('H',(v[0]>>55 for v in struct.iter_unpack('<Q',raw)))
    if sys.byteorder!='little':flags.byteswap()
    return flags.tobytes()
def flags(path,pages):
    raw=gzip.decompress(path.read_bytes())
    if len(raw)!=pages*2:raise ValueError('status vector length mismatch')
    values=[v[0] for v in struct.iter_unpack('<H',raw)]
    if any(v>511 or v&384==384 for v in values):raise ValueError('invalid status bits')
    return values
def read_flags(fd,start,pages):
    raw=os.pread(fd,pages*8,(start//PAGE)*8)
    if len(raw)!=pages*8:raise ValueError('incomplete pagemap range')
    return encode_flags(raw)
def write_gzip(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with gzip.open(path,'wb') as f:f.write(raw)
    return callsite.sha(path.read_bytes())

def capture(folder,binary,pid,identity,record,number):
    started=time.monotonic_ns();exe=Path(f'/proc/{pid}/exe').stat();expected=binary.stat()
    if life.mappings.pid_identity(pid)!=str(identity) or (exe.st_dev,exe.st_ino)!=(expected.st_dev,expected.st_ino):raise ValueError('pagemap identity mismatch')
    before_path=folder/record['file'];raw=gzip.open(before_path,'rt').read()
    if callsite.sha(before_path.read_bytes())!=record['sha256']:raise ValueError('source smaps hash mismatch')
    vmas=selected(raw);total=sum(v['end']-v['start'] for v in vmas)
    if total>MAX_BYTES:raise ValueError('readable unnamed scan exceeds 1GiB; no truncation allowed')
    ranges=[]
    fd=os.open(f'/proc/{pid}/pagemap',os.O_RDONLY)
    try:
        for i,v in enumerate(vmas):
            n=(v['end']-v['start'])//PAGE;first_ns=time.monotonic_ns();a=read_flags(fd,v['start'],n);middle=time.monotonic_ns();b=read_flags(fd,v['start'],n);last=time.monotonic_ns()
            af=f'page-status/{number:03d}-{i:03d}-a.u16le.gz';bf=f'page-status/{number:03d}-{i:03d}-b.u16le.gz'
            ah=write_gzip(folder/af,a);bh=write_gzip(folder/bf,b)
            ranges.append(dict(start=v['start'],end=v['end'],permissions=v['permissions'],path=v['path'],pages=n,first_ns=first_ns,middle_ns=middle,last_ns=last,first_file=af,second_file=bf,first_sha256=ah,second_sha256=bh,first_raw_sha256=callsite.sha(a),second_raw_sha256=callsite.sha(b)))
    finally:os.close(fd)
    after_start=time.monotonic_ns();after=Path(f'/proc/{pid}/smaps').read_text();after_end=time.monotonic_ns();after_file=f'page-status/{number:03d}-after.smaps.gz';after_hash=write_gzip(folder/after_file,after.encode())
    after_vmas=selected(after);new={signature(v) for v in after_vmas};original={signature(v) for v in vmas}
    for r in ranges:r['topology_unchanged']=(r['start'],r['end'],r['permissions'],r['path']) in new
    if life.mappings.pid_identity(pid)!=str(identity):raise ValueError('PID changed during pagemap read')
    finished=time.monotonic_ns()
    if finished-started>MAX_CAPTURE_NS:raise ValueError('pagemap capture exceeded 250ms')
    return dict(key=record['key'],pid=pid,start_ticks=str(identity),source_record_sha256=old.point_sha(record),source_file=record['file'],source_smaps_sha256=record['sha256'],page_started_ns=started,page_finished_ns=finished,after_read_start_ns=after_start,after_read_end_ns=after_end,after_file=after_file,after_sha256=after_hash,ranges=ranges,selected_virtual_bytes=total,added_vmas=[list(x) for x in sorted(new-original)],encoding='upper bits55..63 only, uint16 little-endian; no PFN or swap offset',scope='all readable unnamed VMAs wholly outside known race shadow/metadata bands in source smaps; reservations/named/band-crossing VMAs omitted explicitly; after-added VMAs unobserved')

class Collector:
    def __init__(self,folder,binary,control=False,retained=False):
        self.folder=folder;self.binary=binary.resolve();self.control=control;self.retained=retained;self.records=[];self.seen=set();self.released=False
        self.base=retention.Collector(folder,binary,acknowledger=lambda *_:None) if retained else old.Collector(folder,binary,control)
    def __call__(self):
        self.base()
        active=self.base.active if self.retained else self.base
        if active.pid is None or not active.verified:return
        sources=[('snapshots.json',active.records)]
        if self.retained:sources.append(('retention-snapshots.json',self.base.records))
        for name,rows in sources:
            for record in rows:
                key=(name,record['file'])
                if key in self.seen:continue
                r=capture(self.folder,self.binary,active.pid,active.start,record,len(self.records));r['source_index']=name;self.records.append(r);self.seen.add(key)
                atomic(self.folder/'page-status-index.json',dict(version=1,clock='CLOCK_MONOTONIC',records=self.records,PFNs_saved=False))
        if self.retained and self.base.records and not self.released:
            point=self.base.records[-1]['point']
            if point['phase']=='poststop_gc' and point['at_seconds']>=120:
                # The original native ACK is released only after all page files
                # and their index exist. No original ACK fields are changed.
                decision=dict(release_ns=time.monotonic_ns(),page_index_sha256=callsite.sha((self.folder/'page-status-index.json').read_bytes()),last_page_finished_ns=self.records[-1]['page_finished_ns'],key=self.records[-1]['key'])
                atomic(self.folder/'page-observer-ack.json',decision)
                report=json.loads((self.folder/'native/report.json').read_text());retention.acknowledge(self.folder,report,self.base.records);self.released=True

def union(ranges):
    result=[]
    for lo,hi in sorted(ranges):
        if result and lo<=result[-1][1]:result[-1]=(result[-1][0],max(hi,result[-1][1]))
        else:result.append((lo,hi))
    return result
def at_page(lo,state,starts):
    i=bisect.bisect_right(starts,lo)-1
    if i>=0 and state[i][0]<=lo and lo+PAGE<=state[i][1]:return state[i][2:]
    return ('unresolved',None)
def stats(values):
    return dict(pages=len(values),present_pages=sum(bool(v&256) for v in values),swapped_pages=sum(bool(v&128) for v in values),neither_pages=sum(not v&384 for v in values),flag_histogram=dict(Counter(str(v) for v in values)))
def page_origin(lo,before,final,bs,fs,unstable,us,topology):
    u=bisect.bisect_right(us,lo+PAGE-1)-1;changing=u>=0 and unstable[u][1]>lo
    left=at_page(lo,before,bs);right=at_page(lo,final,fs)
    if topology and not changing and left==right and left[0]==life.LABEL and left[1] is not None:return left
    return ('unresolved',None)
def analyze(folder,parsed):
    index=json.loads((folder/'page-status-index.json').read_text())
    if index['version']!=1 or index['clock']!='CLOCK_MONOTONIC' or index['PFNs_saved'] is not False:raise ValueError('bad page status schema')
    sources={n:json.loads((folder/n).read_text())['records'] for n in {r['source_index'] for r in index['records']}}
    wanted=[(n,r['file']) for n in ('snapshots.json','retention-snapshots.json') if n in sources for r in sources[n]]
    if [(r['source_index'],r['source_file']) for r in index['records']]!=wanted:raise ValueError('missing/duplicate page checkpoint')
    result=[]
    for r in index['records']:
        source=next(s for s in sources[r['source_index']] if s['file']==r['source_file'])
        if old.point_sha(source)!=r['source_record_sha256'] or source['key']!=r['key'] or r['pid']!=parsed['native_pid'] or r['start_ticks']!=str(source['start_ticks']):raise ValueError('page/source binding mismatch')
        start,end=r['page_started_ns'],r['page_finished_ns']
        if not parsed['target_exec_ns']<=source['read_end_monotonic_ns']<=start<=end or end-start>MAX_CAPTURE_NS:raise ValueError('page clock mismatch')
        paths=[r['source_file'],r['after_file']]+[x[k] for x in r['ranges'] for k in ('first_file','second_file')]
        if any(Path(p).is_absolute() or '..' in Path(p).parts for p in paths):raise ValueError('unsafe status path')
        if callsite.sha((folder/r['source_file']).read_bytes())!=r['source_smaps_sha256'] or callsite.sha((folder/r['after_file']).read_bytes())!=r['after_sha256']:raise ValueError('page smaps hash mismatch')
        vmas=selected(gzip.open(folder/r['source_file'],'rt').read());after=selected(gzip.open(folder/r['after_file'],'rt').read());after_set={signature(v) for v in after}
        if [(v['start'],v['end']) for v in vmas]!=[(v['start'],v['end']) for v in r['ranges']]:raise ValueError('selected page range coverage mismatch')
        if sum(v['end']-v['start'] for v in vmas)!=r['selected_virtual_bytes'] or r['selected_virtual_bytes']>MAX_BYTES:raise ValueError('page range size mismatch')
        if r['added_vmas']!=[list(x) for x in sorted(after_set-{signature(v) for v in vmas})]:raise ValueError('added range disclosure mismatch')
        before=life.replay(parsed['calls'],start);final=life.replay(parsed['calls'],end);bs=[x[0] for x in before];fs=[x[0] for x in final]
        unstable=union([bounds for c in parsed['calls'] if c['start_ns']<=end and c['end_ns']>=start for bounds in life.affected(c)]);us=[x[0] for x in unstable]
        ranges=[]
        for v,x in zip(vmas,r['ranges']):
            topology=signature(v) in after_set
            if x['topology_unchanged']!=topology or not start<=x['first_ns']<=x['middle_ns']<=x['last_ns']<=r['after_read_start_ns']<=r['after_read_end_ns']<=end:raise ValueError('range topology/clock mismatch')
            for key,h in [('first_file','first_sha256'),('second_file','second_sha256')]:
                if callsite.sha((folder/x[key]).read_bytes())!=x[h]:raise ValueError('page vector hash mismatch')
            a=flags(folder/x['first_file'],x['pages']);b=flags(folder/x['second_file'],x['pages'])
            if callsite.sha(gzip.decompress((folder/x['first_file']).read_bytes()))!=x['first_raw_sha256'] or callsite.sha(gzip.decompress((folder/x['second_file']).read_bytes()))!=x['second_raw_sha256']:raise ValueError('raw status hash mismatch')
            if x['pages']*PAGE!=v['end']-v['start']:raise ValueError('page number mismatch')
            by_origin={};generations={}
            for i,(fa,fb) in enumerate(zip(a,b)):
                lo=v['start']+i*PAGE;label,gen=page_origin(lo,before,final,bs,fs,unstable,us,topology);known=label==life.LABEL
                q=by_origin.setdefault(label,dict(pages=0,present_first=0,present_second=0,swapped_first=0,swapped_second=0));q['pages']+=1;q['present_first']+=bool(fa&256);q['present_second']+=bool(fb&256);q['swapped_first']+=bool(fa&128);q['swapped_second']+=bool(fb&128)
                if known:
                    q=generations.setdefault(gen,dict(pages=0,present_first=0,present_second=0));q['pages']+=1;q['present_first']+=bool(fa&256);q['present_second']+=bool(fb&256)
            ranges.append(dict(start=v['start'],end=v['end'],smaps_rss=v['bytes']['Rss'],topology_unchanged=topology,first=stats(a),second=stats(b),entries_changed=sum(x!=y for x,y in zip(a,b)),residency_changed=sum(bool((x^y)&384) for x,y in zip(a,b)),by_origin=by_origin,by_generation=generations))
        result.append(dict(key=r['key'],page_started_ns=start,page_finished_ns=end,source_smaps_file=r['source_file'],after_smaps_file=r['after_file'],ranges=ranges,added_vmas=r['added_vmas'],scope='page-state observations by stable mapping lineage, never RSS allocation or atomic snapshot'))
    if 'retention-snapshots.json' in sources and not (folder/'page-observer-ack.json').exists():raise ValueError('missing page observer acknowledgment')
    if (folder/'page-observer-ack.json').exists():
        ack=json.loads((folder/'page-observer-ack.json').read_text());prefix=[r for r in index['records'] if r['page_finished_ns']<=ack['release_ns']]
        if not prefix or ack['last_page_finished_ns']!=prefix[-1]['page_finished_ns'] or ack['key']!=prefix[-1]['key']:raise ValueError('page ACK prefix mismatch')
        historical=dict(index,records=prefix)
        if ack['page_index_sha256']!=callsite.sha((json.dumps(historical,indent=2)+'\n').encode()):raise ValueError('page ACK index hash mismatch')
        if ack['key'][0]!='poststop_gc' or ack['key'][1]<120:raise ValueError('page ACK phase mismatch')
        post=[r for r in index['records'] if r['key'][0]=='poststop_go_scavenge']
        if len(post)!=1 or post[0]['page_started_ns']<=ack['release_ns']:raise ValueError('post-scavenge pages precede ACK release')
    return result

def huge(raw,start,end):
    active=False;value=0
    for line in raw.splitlines():
        m=life.mappings.HEADER.fullmatch(line)
        if m:active=(int(m[1],16),int(m[2],16))==(start,end)
        elif active and line.startswith('AnonHugePages:'):value=int(line.split()[1])*1024
    return value
def validate_control(folder,parsed,vmrows,pagerows,mode):
    if [r['key'] for r in vmrows]!=PHASES or [r['key'] for r in pagerows]!=PHASES:raise ValueError('missing pagemap control phase')
    base=vmrows[0]['point']['base'];M=1024*1024;calls=parsed['call_proof']['calls']
    if len(calls)!=1 or calls[0]['size']!=4*M or calls[0]['pointer']!=base:raise ValueError('known call control mismatch')
    initial=None;reusegen=None
    def region(page,lo,hi,present,known_pages):
        rows=[r for r in page['ranges'] if r['start']<hi and lo<r['end']]
        if any(not lo<=r['start']<r['end']<=hi or not r['topology_unchanged'] for r in rows):raise ValueError('control page range unexpectedly crosses guards')
        if any(sum(r[k]['present_pages'] for r in rows)!=present for k in ('first','second')):raise ValueError('split/reuse/move present count mismatch')
        if sum(r['by_origin'].get(life.LABEL,{}).get('pages',0) for r in rows)!=known_pages:raise ValueError('split/reuse/move page lineage mismatch')
    for vm,page in zip(vmrows,pagerows):
        phase=vm['key'];point=vm['point']
        if point['base']!=base or point['thp_disabled']!=int(mode=='disabled'):raise ValueError('control identity/THP marker mismatch')
        state=life.replay(parsed['calls'],page['page_started_ns'])
        if phase in PHASES[:6]:
            origin,gen=life.cover(base,base+4*M,state)
            if origin!=life.LABEL or not gen:raise ValueError('control lineage missing')
            if initial is None:initial=gen
            if initial!=gen:raise ValueError('advice changed generation')
            regions=[r for r in page['ranges'] if r['start']==base and r['end']==base+4*M]
            if len(regions)!=1 or not regions[0]['topology_unchanged']:raise ValueError('control VMA missing')
            r=regions[0];expected=0 if phase in ('untouched','discarded','failed_advice') else 1024
            if any(r[k]['present_pages']!=expected or r[k]['swapped_pages'] for k in ('first','second')):raise ValueError('known present/swap control mismatch')
            expected_rss=0 if phase in ('untouched','read_zero','discarded','failed_advice') else 4*M
            if r['smaps_rss']!=expected_rss or r['by_origin'].get(life.LABEL,{}).get('pages')!=1024:raise ValueError('known RSS/page-lineage mismatch')
            raw=gzip.open(folder/page['source_smaps_file'],'rt').read();ah=huge(raw,base,base+4*M)
            if mode=='disabled' and ah:raise ValueError('THP-disabled control has huge pages')
            if mode=='enabled' and phase=='held' and (point['collapse_result']!=0 or ah<2*M):raise ValueError('positive THP control exposure missing')
        elif phase=='hole':
            if any(a<base+3*M and base+M<b for a,b,_,_ in state):raise ValueError('hole remains mapped')
            if life.cover(base,base+M,state)[1]!=initial or life.cover(base+3*M,base+4*M,state)[1]!=initial:raise ValueError('surviving generation mismatch')
            region(page,base,base+4*M,512,512)
        elif phase=='reused':
            owner,reusegen=life.cover(base+M,base+3*M,state)
            if owner!='unresolved' or not reusegen or reusegen==initial:raise ValueError('reuse inherited old lineage')
            region(page,base,base+4*M,1024,512)
        elif phase=='moved':
            current=point['current'];owner,gen=life.cover(current,current+4*M,state)
            if owner!='unresolved' or not gen or gen==reusegen or any(a<base+3*M and base+M<b for a,b,_,_ in state):raise ValueError('moved mapping generation mismatch')
            region(page,current,current+4*M,1024,0);region(page,base,base+4*M,512,512)
        elif phase=='released':
            current=point['current']
            if any(a<current+4*M and current<b for a,b,_,_ in state):raise ValueError('release not observed')
            region(page,current,current+4*M,0,0)
            actual=life.mappings.parse_smaps(gzip.open(folder/page['after_smaps_file'],'rt').read(),True)['mappings']
            if any(v['start']<current+4*M and current<v['end'] for v in actual):raise ValueError('released VMA still exists')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('binary','control','tracer','artifacts'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();a.artifacts.mkdir(parents=True,exist_ok=False);result=dict(status='failed',qualifies_24h=False,rss_budget=67108864,stages=[])
    try:
        os.environ['BPFTRACE_STRLEN']='256'
        if os.sysconf('SC_PAGE_SIZE')!=PAGE or callsite.sha(a.binary.read_bytes())!=callsite.BINARY_SHA:raise ValueError('frozen ELF/page size required')
        for mode in ('disabled','enabled'):
            folder=a.artifacts/('control-'+mode);collector=Collector(folder,a.control,control=True)
            parsed=life.context.launch(a.control,folder,{1:'control_site'},[str(folder.resolve()),mode],90,a.tracer,program_builder=life.program,auditor=life.parse,poll_hook=collector)
            vmrows=life.snapshots(folder,parsed,True);pages=analyze(folder,parsed);validate_control(folder,parsed,vmrows,pages,mode)
            result['control-'+mode]=dict(ledger=parsed,snapshots=vmrows,pages=pages);result['stages'].append(mode+'_control_passed')
        for duration in ('15s','180s'):
            folder=a.artifacts/duration;native=(folder/'native').resolve();collector=Collector(folder,a.binary,retained=duration=='180s')
            args=['--transport','3','--mode','1','--duration',duration,'--warmup','12s','--sample-interval','5s','--workers','2','--qps','10','--pool-min','16','--pool-max','64','--artifacts',str(native)]
            if duration=='180s':args+=['--post-stop-observe','120s','--diagnostic-go-scavenge','--post-stop-observer-ack']
            parsed=life.context.launch(a.binary,folder,{1:callsite.OWNER},args,450 if duration=='180s' else 120,a.tracer,program_builder=life.program,auditor=life.parse,poll_hook=collector)
            vmrows=life.snapshots(folder,parsed);pages=analyze(folder,parsed);r=json.loads((native/'report.json').read_text());row=dict(ledger=parsed,snapshots=vmrows,pages=pages,errors=[]);result[duration]=row
            if r['settings']['pid']!=parsed['native_pid'] or 'vcs.revision='+callsite.REVISION not in r['build_info']:raise ValueError('report identity mismatch')
            row['events']=life.verify.validate_events(native/'exchanges.jsonl.gz',r);life.verify.validate_engine_logs(native,folder/'native-stderr.log',64,3)
            try:row['resources']=life.verify.validate_report(r,True)
            except ValueError as e:row['errors'].append(str(e))
            result['stages'].append(duration+'_evidence_complete')
        result['status']='diagnostic_passed' if all(not result[d]['errors'] for d in ('15s','180s')) else 'failed'
    except (ValueError,KeyError,OSError,AssertionError,subprocess.SubprocessError) as e:result['error']=type(e).__name__+': '+str(e)
    finally:
        result['files']={str(f.relative_to(a.artifacts)):callsite.sha(f.read_bytes()) for f in a.artifacts.rglob('*') if f.is_file() and f.name!='experiment.json'};callsite.dump(a.artifacts/'experiment.json',result)
    return int(result['status']!='diagnostic_passed')
if __name__=='__main__':raise SystemExit(main())
