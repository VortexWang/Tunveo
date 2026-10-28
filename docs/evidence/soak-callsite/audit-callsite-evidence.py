"""Offline, fixed-source replay of PR36. Never executes archived targets."""
import argparse,hashlib,json,sys,tempfile,zipfile
from pathlib import Path
from unittest.mock import patch
PINS={'soak_callsite_control.py':'ab76a87a1ebe6281b0372c6614f6a70aad8f7660','soak_ret_context.py':'eac5605150e51b9aec336277088e3981616ac28e','soak_mappings.py':'708301538c24476e4d244efb16cc5027c193efd5','verify_soak.py':'e0c0321054c8be6510f190b33d07966aad8635aa'}
DIGEST='0d0e188611cfb478e5afa268f320c98bc1b4967d9dc057d804ec78c0fff1d593'
def sha(b):return hashlib.sha256(b).hexdigest()
def safe(s):return not Path(s).is_absolute() and '..' not in Path(s).parts
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('archive','scripts-dir','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args()
 for n,pin in PINS.items():
  b=(a.scripts_dir/n).read_bytes();assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==pin,n
 assert sha(a.archive.read_bytes())==DIGEST
 sys.path.insert(0,str(a.scripts_dir.resolve()));import soak_callsite_control as c;import verify_soak as v
 with tempfile.TemporaryDirectory() as t:
  root=Path(t)
  with zipfile.ZipFile(a.archive) as z:
   assert z.testzip() is None and len(z.namelist())==len(set(z.namelist())) and all(safe(n) for n in z.namelist());z.extractall(root)
  experiment=root/'experiment';manifest=json.loads((experiment/'experiment.json').read_text())
  assert manifest['status']=='call_control_passed' and manifest['stages']==['known_control_passed','actual_call_control_passed'] and not manifest['qualifies_24h'] and manifest['historical_rss_failures_retained'] and manifest['rss_budget']==v.ACTIVE['rss']==67108864
  assert manifest['tracer_environment']=={'BPFTRACE_STRLEN':'256'}
  for n,h in manifest['files'].items():assert safe(n) and sha((experiment/n).read_bytes())==h,n
  for line in (root/'binary-sha256.txt').read_text().splitlines():
   h,n=line.split();assert sha((root/Path(n).relative_to('artifacts')).read_bytes())==h
  c.extract(root/'original-race.zip',root/'recovered-probe');assert (root/'recovered-probe').read_bytes()==(root/'binaries/probe').read_bytes()
  assert (root/'tracer-source.txt').read_text().strip()=='93c593f6dab2e930d6198cfaa52b29d19a8c0647'
  info=(root/'bpftrace-info.txt').read_text();assert 'unsafe probe: no' in info and 'bfd: yes' in info
  assert any(l in ('ALLOW_UNSAFE_PROBE:BOOL=OFF','ALLOW_UNSAFE_PROBE:UNINITIALIZED=OFF') for l in (root/'tracer-CMakeCache.txt').read_text().splitlines())
  results={}
  for stage,kind,binary in [('control','control',root/'binaries/control'),('qualification','call_control',root/'binaries/probe')]:
   folder=experiment/stage;plan=json.loads((folder/'plan.json').read_text());execution=json.loads((folder/'execution.json').read_text())
   assert plan['binary_sha256']==sha(binary.read_bytes()) and not execution['timed_out'] and execution['exit_code']==0 and execution['group_gone'] and not execution['cleanup_signals'] and execution['target_identity_verified']
   for key,filename in [('target_identity','target-before.stat'),('tracer_identity','tracer-before.stat')]:assert c.context.proc_identity((folder/filename).read_text())==execution[key]
   groups=c.context.owned_groups(execution['process_group'],execution['target_identity'],execution['tracer_identity'],(folder/'tracer-exe.txt').read_text(),Path(execution['command'][2]));assert groups==execution['owned_groups']
   assert not (folder/'bpftrace-stderr.log').read_text()
   recreated=c.context.plan(binary,{int(k):f['symbol'] for k,f in plan['functions'].items()})
   def normalized(f):
    f=dict(f);s=f['disassembly'];f['disassembly']=s[s.index('Disassembly of section'):];return f
   assert {k:normalized(f) for k,f in recreated['functions'].items()}=={k:normalized(f) for k,f in plan['functions'].items()}
   site=c.call_site(recreated)
   # Resolve bytes using temporary local ELF, while auditing the original exec path.
   # Only the path-dependent resolver is substituted; events/identity are unchanged.
   with patch.object(c,'call_site',return_value=site):
    assert c.program(plan)==(folder/'program.bt').read_text()
    replay=json.loads(json.dumps(c.audit((folder/'events.log').read_text(),plan,execution['expected_uid'])))
   assert replay==json.loads((folder/'context-audit.json').read_text())==manifest[kind]
   assert replay['native_pid']==execution['target_identity']['pid'] and replay['target_exec']['path']==plan['binary']
   if stage=='control':
    expected=[json.loads(l) for l in (folder/'native-stdout.log').read_text().splitlines()];key=lambda r:(r['tid'],r['size'],r['pointer'])
    assert len(expected)==32 and len({r['tid'] for r in expected})==4 and sorted(r['size'] for r in expected)==[n*4096 for n in range(1,33)] and sorted(map(key,expected))==sorted(map(key,replay['calls']))
   results[stage]={'native_pid':replay['native_pid'],'target_exec':replay['target_exec'],'events':replay['events'],'launcher_events':replay['launcher_events'],'call_count':len(replay['calls']),'call_tids':len({x['tid'] for x in replay['calls']}),'cumulative_virtual_requested':sum(x['size'] for x in replay['calls']),'site':site}
  native=experiment/'qualification/native';report=json.loads((native/'report.json').read_text())
  assert report['build_info']==manifest['description']['build_info'] and report['settings']['pid']==results['qualification']['native_pid'] and 'vcs.revision='+c.REVISION in report['build_info'] and 'vcs.modified=false' in report['build_info']
  s=report['settings'];assert (report['transport'],report['mode'],s['tls'],s['duration_seconds'],s['warmup_seconds'],s['workers'],s['qps'],s['pool_min'],s['pool_max'])==(3,1,1,15,12,2,10,16,64)
  events=v.validate_events(native/'exchanges.jsonl.gz',report);assert events==manifest['business_events']==269
  v.validate_engine_logs(native,experiment/'qualification/native-stderr.log',64,3)
  resources=v.validate_report(report,True);assert resources==manifest['pilot_resources'] and not resources['qualifies_24h']
  warm=[p for p in report['points'] if p['phase']=='warmup' and p['at_seconds']>=6];measured=[p for p in report['points'] if p['phase']=='measured'];rss={}
  for metric,limit in v.ACTIVE.items():
   baseline=max(p['resources'][metric] for p in warm);peak=max(p['resources'][metric] for p in measured);assert all(0<p['resources'][metric]<=baseline+limit for p in measured)
   if metric=='rss':rss={'baseline':baseline,'peak':peak,'delta':peak-baseline,'budget':limit,'measured_points':len(measured),'pilot_trend_delta':resources['resource_trend']['rss'],'trend_enforced_in_pilot':False}
  result={'audit_status':'independently_replayed','execution_source':'ed10f1438a675f677fd13aba9a6b241d0f9cf2d1','source_blobs':PINS,'archive_sha256':DIGEST,'native_binary_sha256':c.BINARY_SHA,'source_checkout_of_native_binary':c.REVISION,'business_events':events,'stages':results,'pilot_rss':rss,'qualifies_24h':False,'historical_failures_retained':True,'limitations':'No archived tracer ELF: only its recorded hash, source and build/configuration logs are available. No offline execution of targets. Callsite/ELF checks and original-event replay establish this path only; cumulative virtual requests are neither RSS ownership nor live object bytes. No munmap/mremap/madvise generation ledger, 180s/three-cycle replay, or tracer overhead control in this run.'}
  a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
