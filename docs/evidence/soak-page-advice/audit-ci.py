"""Independently replay PR31 original and corrected CI ZIPs; never launch probes."""
import argparse
from bisect import bisect_right
from collections import Counter
import hashlib,json,re,sys,tempfile,zipfile
from pathlib import Path

PINS = {"soak_page_advice.py":"ec71acdcd4c2df95198f4108dc1499a7307f2424","soak_mapping_ledger.py":"610a54d636767bf92752bd165b60faafd961c7be","soak_mapping_retention.py":"1796b76f75a35c0b6245350244e260efae53345b","soak_ret_context.py":"eac5605150e51b9aec336277088e3981616ac28e","soak_mappings.py":"708301538c24476e4d244efb16cc5027c193efd5","verify_soak.py":"e0c0321054c8be6510f190b33d07966aad8635aa","audit_soak_os_memory.py":"0c5fbff721f98f94fb75f431da968679908d1171","audit_soak_retention.py":"3b06a71491258e62326f4d3d7f4dc4bdae10ca0b"}
CHECKOUT='aa0619065e6eac26fb560f9c046013f1c30acde6'
INITIAL_SHA='806588cb811124dcd47c579e7e13872ee7a963acd1249a612d5e3cc0f6df06d2'

def canon(x):return json.loads(json.dumps(x))
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def unpack(path,sha,root):
 assert digest(path)==sha
 with zipfile.ZipFile(path) as z:
  assert z.testzip() is None
  assert len(set(z.namelist()))==len(z.namelist())
  assert all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in z.namelist());z.extractall(root)

def family_intersections(call,maps,l):
 """Stable virtual mapping overlaps, not resident/reclaimed byte estimates."""
 addr,length,_=call['args'];lo=addr//l.PAGE*l.PAGE;hi=l.rounded(addr+length) if length else lo
 before=l.replay(maps,call['start_ns']);after=l.replay(maps,call['end_ns']);out=[]
 for a,b,owner,gen in before:
  if owner!='observed_race_runtime' or b<=lo or a>=hi:continue
  for c,d,label,newgen in after:
   if (label,newgen)!=(owner,gen) or d<=lo or c>=hi:continue
   x,y=max(a,c,lo),min(b,d,hi)
   if x>=y:continue
   changed=any(m['start_ns']<=call['end_ns'] and m['end_ns']>=call['start_ns'] and
       any(s<y and x<e for s,e in l.affected(m)) for m in maps)
   if not changed:out.append(dict(start=x,end=y,generation=gen))
 return out

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',type=Path,required=True);p.add_argument('--sha256',required=True);p.add_argument('--initial-archive',type=Path,required=True);p.add_argument('--scripts-dir',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--summary',type=Path);a=p.parse_args()
 for name,expected in PINS.items():
  raw=(a.scripts_dir/name).read_bytes();assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==expected,name
 sys.path.insert(0,str(a.scripts_dir.resolve()))
 import soak_page_advice as page,soak_mapping_ledger as l,soak_mapping_retention as r,soak_ret_context as c,verify_soak as v,audit_soak_os_memory as rollup
 # Replay is pure; retain the input object to avoid id reuse, and memoize
 # repeated completed-call states. Full CI output still matches exactly.
 replay=l.replay;memo={}
 def cached_replay(calls,at):
  if id(calls) not in memo:
   ends=[c['end_ns'] for c in calls];assert ends==sorted(ends)
   memo[id(calls)]=(calls,ends,{})
  entry=memo[id(calls)];assert entry[0] is calls;count=bisect_right(entry[1],at)
  if count not in entry[2]:entry[2][count]=replay(calls,at)
  return entry[2][count]
 l.replay=cached_replay
 with tempfile.TemporaryDirectory(prefix='pr31-replay-') as tmp:
  root=Path(tmp);initial=root/'initial';current=root/'current';unpack(a.initial_archive,INITIAL_SHA,initial);unpack(a.archive,a.sha256,current)
  enter=(initial/'madvise-enter-layout.txt').read_text();exit=(initial/'madvise-exit-layout.txt').read_text()
  assert not all(x in enter for x in ('start;','len_in;','behavior;'))
  page.validate_layout(enter,exit);assert not (initial/'experiment').exists()
  page.validate_layout((current/'madvise-enter-layout.txt').read_text(),(current/'madvise-exit-layout.txt').read_text())
  assert (current/'tracer-source.txt').read_text().strip()=='93c593f6dab2e930d6198cfaa52b29d19a8c0647'
  info=(current/'bpftrace-info.txt').read_text();assert 'bfd: yes' in info and 'unsafe probe: no' in info
  original=json.loads((current/'experiment/experiment.json').read_text());exp=current/'experiment';stages={}
  assert original['pilot_only'] and not original['qualifies_24h']
  for name,control in [('control',True),('pilot',False)]:
   folder=exp/name;execution=json.loads((folder/'execution.json').read_text());plan=json.loads((folder/'plan.json').read_text())
   assert execution['exit_code']==0 and not execution['timed_out'] and not execution['cleanup_signals'] and execution['group_gone'] and execution['target_identity_verified']
   target=c.proc_identity((folder/'target-before.stat').read_text());parent=c.proc_identity((folder/'tracer-before.stat').read_text())
   assert target==execution['target_identity'] and parent==execution['tracer_identity']
   assert c.owned_groups(execution['process_group'],target,parent,(folder/'tracer-exe.txt').read_text(),Path(execution['command'][2]))==execution['owned_groups']
   assert not re.search(r'(?i)lost|dropped|error|failed',(folder/'bpftrace-stderr.log').read_text())
   symbols=l.CONTROL if control else c.SYMBOLS
   assert {k:f['symbol'] for k,f in plan['functions'].items()}=={str(k):v for k,v in symbols.items()}
   for kind,f in plan['functions'].items():
    assert c.ret_sites(f['disassembly'],f['address'],f['size'])==f['ret_offsets']
    tails=f.get('tail_exits',[]);assert not tails or (kind=='1' and all(t['symbol']=='_ZN6__tsan10SlotUnlockEPNS_11ThreadStateE' for t in tails))
    assert c.tail_sites(f['disassembly'],f['address'],f['size'],{t['target']:t['symbol'] for t in tails})==tails
   parsed=page.parse((folder/'events.log').read_text(),plan,execution['expected_uid'])
   assert canon(parsed)==json.loads((folder/'context-audit.json').read_text())==original[name]['ledger']
   rows=l.audit_snapshots(folder,parsed,not control,control,**({'control_validator':page.validate_control} if control else {}))
   assert canon(rows)==original[name]['snapshots']
   advice=page.audit_advice(folder,parsed,not control)
   assert canon(advice)==(original['control']['advice'] if control else original['advice'])
   if control:
    records=json.loads((folder/'snapshots.json').read_text())['records'];calls=[x for x in parsed['calls'] if x['call']=='madvise']
    for call,prev,next in zip(calls,[0,1,4],[1,2,5]):
     assert records[prev]['read_end_monotonic_ns']<call['start_ns']<=call['end_ns']<rows[next]['point']['monotonic_ns']
   stages[name]=dict(ledger=parsed,rows=rows,advice=advice,execution=execution)
  folder=exp/'pilot';native=folder/'native';report=json.loads((native/'report.json').read_text());parsed=stages['pilot']['ledger']
  assert report['build_info']==original['description']['build_info'] and 'vcs.modified=false' in report['build_info'] and '-race=true' in report['build_info'] and CHECKOUT in report['build_info']
  s=report['settings'];assert (report['transport'],report['mode'],s['tls'],s['duration_seconds'],s['warmup_seconds'],s['sample_interval_seconds'],s['pool_min'],s['pool_max'],s['workers'],s['qps'])==(3,1,1,180,12,5,16,64,2,10)
  assert s['pid']==parsed['native_pid']
  post=r.audit_retention(folder,parsed,report);r.add_load_comparisons(folder,parsed,report,post);assert canon(post)==original['retention']
  records=json.loads((folder/'retention-snapshots.json').read_text())['records'];bounds=[(x['read_start_monotonic_ns']-round(x['point']['at_seconds']*1e9)-100000000,x['read_start_monotonic_ns']-round(x['point']['at_seconds']*1e9)) for x in records]
  clock_origin=[max(x[0] for x in bounds),min(x[1] for x in bounds)];assert clock_origin[0]<=clock_origin[1]
  events=v.validate_events(native/'exchanges.jsonl.gz',report);assert events==original['events'];v.validate_engine_logs(native,folder/'native-stderr.log',64,3)
  error=None;acceptance=None
  try:acceptance=v.validate_report(report,True)
  except ValueError as e:error='ValueError: '+str(e)
  assert (original['status']=='diagnostic_passed')==(error is None) and original.get('error')==error and original.get('acceptance')==acceptance
  assert v.ACTIVE['rss']==64*1048576
  warm=[x for x in report['points'] if x['phase']=='warmup' and x['at_seconds']>=6];measured=[x for x in report['points'] if x['phase']=='measured'];b=max(warm,key=lambda x:x['resources']['rss']);peak=max(measured,key=lambda x:x['resources']['rss'])
  maps=l.prepare([dict(x,owner='observed_race_runtime' if x['contexts'] else 'unresolved') for x in parsed['calls'] if x['call']!='madvise'])
  overlap=[]
  for call in parsed['calls']:
   if call['call']=='madvise':overlap.append(dict(id=call['id'],virtual_stable_family_intersections=family_intersections(call,maps,l)))
  hashes={line.split()[1]:line.split()[0] for line in (current/'binary-sha256.txt').read_text().splitlines()}
  for name,key in [('control','bin/advice-control'),('pilot','bin/probe')]:assert json.loads((exp/name/'plan.json').read_text())['binary_sha256']==hashes[key]
  result=dict(audit_status='independently_replayed',original_status=original['status'],original_error=error,qualifies_24h=False,
    budget=dict(baseline_at_seconds=b['at_seconds'],peak_at_seconds=peak['at_seconds'],baseline_rss=b['resources']['rss'],peak_rss=peak['resources']['rss'],delta_bytes=peak['resources']['rss']-b['resources']['rss'],allowance_bytes=v.ACTIVE['rss']),counts=report['counts'],events=events,measured_seconds=report['measured_seconds'],
    control=dict(snapshots=stages['control']['rows'],advice=stages['control']['advice']),retention=post,advice=stages['pilot']['advice'],stable_family_virtual_overlaps=overlap,
    capture=dict(events=parsed['events'],memory_syscalls=dict(Counter(x['call'] for x in parsed['calls'])),load_snapshots=len(stages['pilot']['rows']),poststop_snapshots=len(post['snapshots'])),
    pinned_source_blobs=PINS,clock_origin_interval_ns=clock_origin,rollup=rollup.audit(native/'report.json'),
    initial_layout_failure=dict(status='failed',go_coverage=False,original_check_still_fails=True,corrected_schema_accepts=True,artifact_sha256=INITIAL_SHA),
    source_build_info=report['build_info'],original_file_sha256={str(f.relative_to(current)):digest(f) for f in sorted(current.rglob('*')) if f.is_file()})
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
 if a.summary:
  summary=canon(result)
  def compact(row):return dict(key=row['key'],resources={k:v for k,v in row['point']['resources'].items() if k!='os_memory'},family_groups=row['family']['groups_rss_bytes'])
  summary['retention']['selected']={k:compact(v) for k,v in post['selected'].items()};summary['retention']['snapshots']=[compact(x) for x in post['snapshots']]
  summary['control']=dict(stages=[dict(key=x['key'],point=x['point'],groups=x['groups_rss_bytes']) for x in stages['control']['rows']],advice=stages['control']['advice']['events'])
  summary['advice']=dict(counts=result['advice']['counts'],event_count=len(result['advice']['events']),scope=result['advice']['scope'])
  summary['stable_family_virtual_overlaps']=[x for x in overlap if x['virtual_stable_family_intersections']]
  a.summary.parent.mkdir(parents=True,exist_ok=True);a.summary.write_text(json.dumps(summary,indent=2)+'\n')
 print(json.dumps({k:result[k] for k in ['audit_status','original_status','original_error','budget','capture']}))

if __name__=='__main__':main()
