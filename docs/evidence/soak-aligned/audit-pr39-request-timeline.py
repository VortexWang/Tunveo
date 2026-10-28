"""Recount historical 2MiB request generations without naming their caller."""
import bisect,gzip,hashlib,json,struct,sys,tempfile,zipfile
from pathlib import Path
from unittest.mock import patch
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    archive,source,output=map(Path,sys.argv[1:]);assert sha(archive.read_bytes())=='616f8c4da929312196c654dda4c28dac997ba12c1eafdd4b8caa32f920bc7850'
    sys.path.insert(0,str(source.resolve()));import soak_pagemap as p
    result=dict(artifact=12813365084,archive_sha256=sha(archive.read_bytes()),request_origin='unresolved in PR39; new-run AP32 qualification must not be applied retroactively',scope='Stable historical virtual generation and present status counts, never RSS/PSS or physical exclusive bytes',selected=[])
    with zipfile.ZipFile(archive) as z,tempfile.TemporaryDirectory() as t:
        binary=Path(t)/'probe';binary.write_bytes(z.read('binaries/probe'));local=p.life.context.plan(binary,{1:p.callsite.OWNER});site=p.callsite.call_site(local)
        folder='experiment/180s/';plan=json.loads(z.read(folder+'plan.json'));saved=json.loads(z.read(folder+'context-audit.json'));run=json.loads(z.read(folder+'execution.json'))
        with patch.object(p.callsite,'call_site',return_value=site):parsed=json.loads(json.dumps(p.life.parse(z.read(folder+'events.log').decode(),plan,run['expected_uid'])))
        assert parsed==saved
        calls=parsed['calls'];wanted={c['id']:c for c in calls if c['call']=='mmap' and c['args']==[0,2097152,3,34] and p.life.success(c) and not c['ambiguous']}
        report=json.loads(z.read(folder+'native/report.json'));index=json.loads(z.read(folder+'page-status-index.json'));warm=max((r for r in report['points'] if r['phase']=='warmup' and r['at_seconds']>=6),key=lambda r:r['resources']['rss']);peak=max((r for r in report['points'] if r['phase']=='measured'),key=lambda r:r['resources']['rss']);post=report['post_stop_observation'][-1]
        for point in (warm,peak,post):
            row=next(r for r in index['records'] if r['key']==[point['phase'],point['at_seconds']]);start,end=row['page_started_ns'],row['page_finished_ns'];before=p.life.replay(calls,start);after=p.life.replay(calls,end);bs=[r[0] for r in before];fs=[r[0] for r in after]
            unstable=p.union([bounds for c in calls if c['start_ns']<=end and c['end_ns']>=start for bounds in p.life.affected(c)]);us=[r[0] for r in unstable];counts=dict(pages=0,present_first=0,present_second=0)
            for q in row['ranges']:
                if not q['topology_unchanged']:continue
                values=[]
                for name,h in [('first_file','first_sha256'),('second_file','second_sha256')]:
                    data=z.read(folder+q[name]);assert sha(data)==q[h];raw=gzip.decompress(data);assert len(raw)==q['pages']*2;values.append([r[0] for r in struct.iter_unpack('<H',raw)])
                for i,(fa,fb) in enumerate(zip(*values)):
                    lo=q['start']+i*4096;left=p.at_page(lo,before,bs);right=p.at_page(lo,after,fs);u=bisect.bisect_right(us,lo+4095)-1;changing=u>=0 and unstable[u][1]>lo
                    if left!=right or changing or left[1] not in wanted:continue
                    counts['pages']+=1;counts['present_first']+=bool(fa&256);counts['present_second']+=bool(fb&256)
            generations={g for lo,hi,owner,g in after if g in wanted}
            result['selected'].append(dict(key=row['key'],mmap_requests_completed_before_page_capture=sum(c['end_ns']<start for c in wanted.values()),surviving_generations=len(generations),surviving_virtual_bytes=sum(hi-lo for lo,hi,owner,g in after if g in wanted),**counts))
        result['total_2MiB_requests']=len(wanted);output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
