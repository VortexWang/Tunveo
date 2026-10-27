"""Offline replay of the PR30 CI archive; no probes or permission changes."""
import argparse,gzip,hashlib,json,re,sys,zipfile,tempfile
from pathlib import Path
SOURCE_BLOBS = {"soak_mapping_retention.py":"1796b76f75a35c0b6245350244e260efae53345b","soak_mapping_ledger.py":"23c39d668502b4f3865a6e9347b0bed811f0a1c9","soak_ret_context.py":"eac5605150e51b9aec336277088e3981616ac28e","soak_mappings.py":"708301538c24476e4d244efb16cc5027c193efd5","verify_soak.py":"e0c0321054c8be6510f190b33d07966aad8635aa","audit_soak_os_memory.py":"0c5fbff721f98f94fb75f431da968679908d1171","audit_soak_retention.py":"3b06a71491258e62326f4d3d7f4dc4bdae10ca0b"}

def canon(x):return json.loads(json.dumps(x))
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',type=Path,required=True);p.add_argument('--sha256',required=True);p.add_argument('--scripts-dir',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--summary',type=Path);a=p.parse_args()
 for name,expected in SOURCE_BLOBS.items():
  raw=(a.scripts_dir/name).read_bytes();assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==expected,name
 sys.path.insert(0,str(a.scripts_dir.resolve()))
 import soak_mapping_ledger as l,soak_ret_context as c,soak_mapping_retention as r,verify_soak as v,audit_soak_os_memory as osmem
 assert digest(a.archive)==a.sha256
 with tempfile.TemporaryDirectory(prefix='pr30-offline-') as tmp:
  root=Path(tmp)
  with zipfile.ZipFile(a.archive) as z:
   assert z.testzip() is None and all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in z.namelist());z.extractall(root)
  assert (root/'tracer-source.txt').read_text().strip()=='93c593f6dab2e930d6198cfaa52b29d19a8c0647'
  info=(root/'bpftrace-info.txt').read_text();assert 'bfd: yes' in info and 'unsafe probe: no' in info
  exp=root/'experiment';original=json.loads((exp/'experiment.json').read_text());stages={}
  assert original['pilot_only'] and original['qualifies_24h'] is False
  for name,control in [('control',True),('pilot',False)]:
   folder=exp/name;execution=json.loads((folder/'execution.json').read_text())
   assert execution['exit_code']==0 and not execution['timed_out'] and not execution['cleanup_signals'] and execution['group_gone'] and execution['target_identity_verified']
   target=c.proc_identity((folder/'target-before.stat').read_text());parent=c.proc_identity((folder/'tracer-before.stat').read_text())
   assert target==execution['target_identity'] and parent==execution['tracer_identity']
   assert c.owned_groups(execution['process_group'],target,parent,(folder/'tracer-exe.txt').read_text(),Path(execution['command'][2]))==execution['owned_groups']
   assert not re.search(r'(?i)lost|dropped|error|failed',(folder/'bpftrace-stderr.log').read_text())
   plan=json.loads((folder/'plan.json').read_text());symbols=l.CONTROL if control else c.SYMBOLS
   assert {k:x['symbol'] for k,x in plan['functions'].items()}=={str(k):s for k,s in symbols.items()}
   for kind,f in plan['functions'].items():
    assert c.ret_sites(f['disassembly'],f['address'],f['size'])==f['ret_offsets']
    tails=f.get('tail_exits',[]);assert not tails or (kind=='1' and all(t['symbol']=='_ZN6__tsan10SlotUnlockEPNS_11ThreadStateE' for t in tails))
    assert c.tail_sites(f['disassembly'],f['address'],f['size'],{t['target']:t['symbol'] for t in tails})==tails
   parsed=l.parse((folder/'events.log').read_text(),plan,execution['expected_uid'])
   assert canon(parsed)==json.loads((folder/'context-audit.json').read_text())==original[name]['ledger']
   rows=l.audit_snapshots(folder,parsed,not control,control);assert canon(rows)==original[name]['snapshots']
   stages[name]=dict(ledger=parsed,snapshots=rows,execution=execution)
  folder=exp/'pilot';native=folder/'native';report=json.loads((native/'report.json').read_text())
  assert report['build_info']==original['description']['build_info'] and 'vcs.modified=false' in report['build_info'] and '-race=true' in report['build_info']
  assert 'vcs.revision=5c70c5d433d0b533a1b039239e92c0eec56ff24c' in report['build_info']
  s=report['settings'];assert (report['transport'],report['mode'],s['tls'],s['duration_seconds'],s['warmup_seconds'],s['sample_interval_seconds'],s['pool_min'],s['pool_max'],s['workers'],s['qps'])==(3,1,1,180,12,5,16,64,2,10)
  assert s['pid']==stages['pilot']['ledger']['native_pid']
  post=r.audit_retention(folder,stages['pilot']['ledger'],report);r.add_load_comparisons(folder,stages['pilot']['ledger'],report,post)
  assert canon(post)==original['retention']
  # Check a common monotonic origin interval as an extra independent guard
  # against a late report rewrite making an old point appear newly published.
  records=json.loads((folder/'retention-snapshots.json').read_text())['records']
  intervals=[(x['read_start_monotonic_ns']-round(x['point']['at_seconds']*1e9)-100000000,
              x['read_start_monotonic_ns']-round(x['point']['at_seconds']*1e9)) for x in records]
  origin=[max(x[0] for x in intervals),min(x[1] for x in intervals)];assert origin[0]<=origin[1]
  events=v.validate_events(native/'exchanges.jsonl.gz',report);assert events==original['events']
  v.validate_engine_logs(native,folder/'native-stderr.log',64,3)
  error=None;acceptance=None
  try:acceptance=v.validate_report(report,True)
  except ValueError as e:error='ValueError: '+str(e)
  assert (original['status']=='diagnostic_passed')==(error is None)
  assert original.get('error')==error and original.get('acceptance')==acceptance
  assert v.ACTIVE['rss']==64*1048576
  warm=[x for x in report['points'] if x['phase']=='warmup' and x['at_seconds']>=6];measured=[x for x in report['points'] if x['phase']=='measured']
  baseline=max(warm,key=lambda x:x['resources']['rss']);peak=max(measured,key=lambda x:x['resources']['rss'])
  budget=dict(baseline_at_seconds=baseline['at_seconds'],peak_at_seconds=peak['at_seconds'],baseline_rss=baseline['resources']['rss'],peak_rss=peak['resources']['rss'],delta_bytes=peak['resources']['rss']-baseline['resources']['rss'],allowance_bytes=v.ACTIVE['rss'])
  hashes={line.split()[1]:line.split()[0] for line in (root/'binary-sha256.txt').read_text().splitlines()}
  for name,key in [('control','bin/ledger-control'),('pilot','bin/probe')]:assert json.loads((exp/name/'plan.json').read_text())['binary_sha256']==hashes[key]
  result=dict(audit_status='independently_replayed',original_status=original['status'],original_error=error,qualifies_24h=False,budget=budget,counts=report['counts'],events=events,measured_seconds=report['measured_seconds'],retention=post,rollup=osmem.audit(native/'report.json'),pinned_source_blobs=SOURCE_BLOBS,poststop_clock_origin_interval_ns=origin,
    capture=dict(control_events=stages['control']['ledger']['events'],load_and_retention_events=stages['pilot']['ledger']['events'],load_snapshots=len(stages['pilot']['snapshots']),poststop_snapshots=len(post['snapshots']),memory_syscalls=dict(__import__('collections').Counter(x['call'] for x in stages['pilot']['ledger']['calls']))),
    original_file_sha256={str(f.relative_to(root)):digest(f) for f in sorted(root.rglob('*')) if f.is_file()},source_build_info=report['build_info'])
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ['audit_status','original_status','original_error','budget','capture']}))
 if a.summary:
  summary=canon(result)
  def compact(row):
   return dict(key=row['key'],resources={k:v for k,v in row['point']['resources'].items() if k!='os_memory'},family_groups=row['family']['groups_rss_bytes'])
  summary['retention']['selected']={k:compact(v) for k,v in post['selected'].items()}
  summary['retention']['snapshots']=[compact(row) for row in post['snapshots']]
  a.summary.parent.mkdir(parents=True,exist_ok=True);a.summary.write_text(json.dumps(summary,indent=2)+'\n')

if __name__=='__main__':main()
