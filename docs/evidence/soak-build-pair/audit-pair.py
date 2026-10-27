"""Read-only replay of the fixed PR32 ABBA artifact; never executes a probe."""
import argparse
import hashlib
import json
import sys
import tempfile
import zipfile
from pathlib import Path
PINS={'verify_soak.py':'e0c0321054c8be6510f190b33d07966aad8635aa','soak_build_pair.py':'25f981cf6fdf09b660d73273620834b149932839'}
CHECKOUT='c69d0f0dc646acbcccc98ccd70c29eaa90697919'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',type=Path,required=True);p.add_argument('--sha256',required=True);p.add_argument('--scripts-dir',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    for name,pin in PINS.items():
        b=(a.scripts_dir/name).read_bytes();assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==pin,name
    sys.path.insert(0,str(a.scripts_dir.resolve()));import soak_build_pair as pair;import verify_soak as v
    assert sha(a.archive)==a.sha256
    with tempfile.TemporaryDirectory(prefix='pr32-replay-') as tmp:
        root=Path(tmp)
        with zipfile.ZipFile(a.archive) as z:
            assert z.testzip() is None and len(set(z.namelist()))==len(z.namelist())
            assert all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in z.namelist());z.extractall(root)
        base=root/'artifacts';original=json.loads((base/'pair.json').read_text());assert original['order']==['ordinary','race','race','ordinary'] and len(original['runs'])==4 and not original['qualifies_24h']
        hashes={line.split()[1]:line.split()[0] for line in (root/'pair-meta/binary-sha256.txt').read_text().splitlines()}
        rows=[]
        for i,name in enumerate(original['order']):
            folder=base/f'{i+1}-{name}';saved=original['runs'][i];summary=json.loads((folder/'summary.json').read_text());r=json.loads((folder/'native/report.json').read_text());info=json.loads((root/f'pair-meta/{name}.json').read_text())['build_info']
            assert saved['build']==name and saved['original_summary']==summary
            assert r['build_info']==info and 'vcs.modified=false' in info and 'vcs.revision='+CHECKOUT in info and ('-race=true' in info)==(name=='race')
            assert r['settings']['pid']==summary['native_pid'] and summary['exit_code']==0 and summary['cleanup']=={'reaped':True,'forced_kill':False}
            assert saved['binary_sha256']==summary['binary_sha256']==hashes['bin/'+name] and summary['runner_sha256']==sha(a.scripts_dir/'verify_soak.py')
            for file,digest in summary['files'].items():
                assert not Path(file).is_absolute() and '..' not in Path(file).parts
                assert sha(folder/file)==digest,file
            s=r['settings'];assert (r['transport'],r['mode'],s['tls'],s['duration_seconds'],s['warmup_seconds'],s['sample_interval_seconds'],s['workers'],s['qps'],s['pool_min'],s['pool_max'],s['post_stop_observe_seconds'],s['diagnostic_go_scavenge'])==(3,1,1,180,12,5,2,10,16,64,120,True)
            assert not s.get('post_stop_observer_ack',False)
            diagnostics=pair.resources(r);assert diagnostics==saved['resources'];errors=[];checks={}
            for label,check in [('report',lambda:v.validate_report(r,True)),('events',lambda:v.validate_events(folder/'native/exchanges.jsonl.gz',r)),('logs',lambda:v.validate_engine_logs(folder/'native',folder/'stderr.log',64,3))]:
                try:checks[label]=check();assert checks[label]==saved[label]
                except (ValueError,KeyError,OSError,EOFError) as error:errors.append(label+': '+str(error))
            assert errors==saved['errors']
            assert saved['exit_code']==(0 if summary['status']=='pilot_passed' else 1)
            assert not summary['qualifies_24h'] and v.ACTIVE['rss']==64*1048576
            rows.append({'run':i+1,'build':name,'original_status':summary['status'],'errors':errors,'resources':diagnostics,'events':checks.get('events')})
        status='pilot_passed' if all(x['exit_code']==0 and not x['errors'] for x in original['runs']) else 'failed';assert status==original['status']
        result={'audit_status':'independently_replayed','original_status':status,'qualifies_24h':False,'checkout':CHECKOUT,'source_blobs':PINS,'archive_sha256':a.sha256,'runs':rows,'scope':'Four fresh processes, uninstrumented ABBA pilots on one host; not proof of causal race overhead or 24h behavior.'}
    a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':status,'runs':[{'build':x['build'],'rss_delta_mib':x['resources']['active']['rss']['delta']/1048576,'rss_passed':x['resources']['active']['rss']['passed'],'errors':x['errors']} for x in rows]}))
if __name__=='__main__':main()
