"""Replay fixed PR33 raw artifacts without executing native probes."""
import argparse,gzip,hashlib,json,sys,tempfile,zipfile
from pathlib import Path
PINS={'verify_soak.py':'e0c0321054c8be6510f190b33d07966aad8635aa','soak_build_pair.py':'25f981cf6fdf09b660d73273620834b149932839','soak_cycles.py':'6c4271b3e1f7e6760357cf7c1c4334c50e0a3c27'}
CHECKOUT='cca2d7dc3c4dfff8642e12eb9819d506bf25b1d4'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('archive','scripts-dir','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--sha256',required=True);a=p.parse_args()
 for name,pin in PINS.items():
  raw=(a.scripts_dir/name).read_bytes();assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==pin
 sys.path.insert(0,str(a.scripts_dir.resolve()));import soak_cycles as c;import verify_soak as v
 assert digest(a.archive)==a.sha256
 with tempfile.TemporaryDirectory(prefix='pr33-replay-') as t:
  root=Path(t)
  with zipfile.ZipFile(a.archive) as z:
   assert z.testzip() is None and len(set(z.namelist()))==len(z.namelist());assert all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in z.namelist());z.extractall(root)
  original=json.loads((root/'cycles.json').read_text());assert not original['qualifies_24h'] and [r['build'] for r in original['runs']]==['ordinary','race']
  for path,h in original['files'].items():
   assert not Path(path).is_absolute() and '..' not in Path(path).parts;assert digest(root/path)==h,path
  out=[]
  for saved in original['runs']:
   name=saved['build'];assert saved['exit_code']==0
   info=saved['build_info'];assert 'vcs.revision='+CHECKOUT in info and 'vcs.modified=false' in info and ('-race=true' in info)==(name=='race')
   reports=[];errors=[];events=[];mapping_counts=[];previous=-1
   for i in range(1,4):
    folder=root/name/f'cycle-{i}';r=json.loads((folder/'report.json').read_text());reports.append(r)
    assert r['build_info']==info and r['settings']['pid']==saved['pid']
    s=r['settings'];assert (r['transport'],r['mode'],s['tls'],s['duration_seconds'],s['warmup_seconds'],s['sample_interval_seconds'],s['workers'],s['qps'],s['pool_min'],s['pool_max'],s['post_stop_observe_seconds'],s['diagnostic_go_scavenge'])==(3,1,1,180,12,5,2,10,16,64,120,True)
    assert not s.get('post_stop_observer_ack',False)
    for label,fn in [('report',lambda:v.validate_report(r,True)),('events',lambda:v.validate_events(folder/'exchanges.jsonl.gz',r)),('logs',lambda:v.validate_engine_logs(folder,root/(name+'-stderr.log'),64,3))]:
     try:
      value=fn()
      if label=='events':events.append(value)
     except (ValueError,KeyError,OSError,EOFError) as e:errors.append(f'cycle-{i} {label}: {e}')
    records=[json.loads(x) for x in (folder/'mapping-index.jsonl').read_text().splitlines()];assert len(records)>=68
    assert records[-1]['load_points']==len(r['points']) and records[-1]['retention_points']==len(r['post_stop_observation'])
    for record in records:
     assert record['pid']==saved['pid'] and record['cycle']==i and previous<=record['read_start_monotonic_ns']<=record['read_end_monotonic_ns'];previous=record['read_end_monotonic_ns']
     path=Path(record['file']);assert not path.is_absolute() and '..' not in path.parts
     assert hashlib.sha256(gzip.decompress((folder/path).read_bytes())).hexdigest()==record['sha256_raw']
    mapping_counts.append(len(records))
   fixed=c.fixed_envelope(reports);assert fixed==saved['fixed_envelope']
   if not fixed['passed']:errors.append('original first-cycle fixed active envelope exceeded')
   assert errors==saved['errors']
   out.append({'build':name,'pid':saved['pid'],'errors':errors,'fixed_envelope':fixed,'audited_events':events,'mapping_counts':mapping_counts})
  status='diagnostic_passed' if all(not r['errors'] for r in out) else 'failed';assert status==original['status']
  result={'audit_status':'independently_replayed','original_status':status,'qualifies_24h':False,'checkout':CHECKOUT,'source_blobs':PINS,'archive_sha256':a.sha256,'runs':out,'scope':'Diagnostic GC/scavenge and smaps overhead retained; equal virtual addresses do not establish mapping generations or object reuse.'}
 a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':status,'runs':[{'build':r['build'],'pid':r['pid'],'events':r['audited_events'],'mapping_counts':r['mapping_counts'],'errors':r['errors']} for r in out]}))
if __name__=='__main__':main()
