"""Run from repository root after placing original ZIPs and ci-metadata.json in artifacts/ret-context."""
from pathlib import Path
import json,hashlib,zipfile,re,sys
sys.path.insert(0,'scripts')
import soak_ret_context as c
import verify_soak as v
base=Path('artifacts/ret-context');cases=json.loads((base/'ci-metadata.json').read_text());result={}
canon=lambda x:json.loads(json.dumps(x))
SLOT='_ZN6__tsan10SlotUnlockEPNS_11ThreadStateE'


def stage(folder,expected_hash,accept_context):
 e=json.loads((folder/'execution.json').read_text());p=json.loads((folder/'plan.json').read_text())
 assert p['binary_sha256']==expected_hash
 for kind,f in p['functions'].items():
  assert c.ret_sites(f['disassembly'],f['address'],f['size'])==f['ret_offsets']
  tails=f.get('tail_exits',[])
  if tails:assert kind=='1' and all(x['symbol']==SLOT for x in tails)
  try:actual=c.tail_sites(f['disassembly'],f['address'],f['size'],{x['target']:x['symbol'] for x in tails})
  except ValueError as error:
   assert not accept_context and kind=='1' and not tails and str(error)=='unplanned function-range exit'
  else:assert actual==tails
 assert e['exit_code']==0 and not e['timed_out'] and e['group_gone'] and not e['cleanup_signals'] and e['target_identity_verified']
 target=c.proc_identity((folder/'target-before.stat').read_text());parent=c.proc_identity((folder/'tracer-before.stat').read_text())
 assert target==e['target_identity'] and parent==e['tracer_identity']
 assert c.owned_groups(e['process_group'],target,parent,(folder/'tracer-exe.txt').read_text(),Path(e['command'][2]))==e['owned_groups']
 stderr=(folder/'bpftrace-stderr.log').read_text();assert not re.search(r'(?i)lost|dropped|error|failed',stderr)
 raw=(folder/'events.log').read_text();records=[json.loads(x) for x in raw.splitlines() if x.startswith('{') and json.loads(x)['event'] not in ('begin','end')]
 ledger={int(k):int(n) for k,n in re.findall(r'@seq\[(\d+)\]: (\d+)',raw)};threads={}
 for row in records:threads.setdefault(row['tid'],[]).append(row)
 assert threads.keys()==ledger.keys()
 for tid,rows in threads.items():assert sorted(x['seq'] for x in rows)==list(range(1,ledger[tid]+1))
 error=None;audit=None
 try:audit=c.audit_events(raw,p,e['expected_uid'])
 except ValueError as ex:error=str(ex)
 if accept_context:
  assert error is None
  stored=json.loads((folder/'context-audit.json').read_text())
  assert all(canon(audit)[k]==value for k,value in stored.items() if k!='scope')
  if 'matched_tail_exits_by_kind' not in stored:assert audit['matched_tail_exits_by_kind']=={}
  assert audit['native_pid']==target['pid']
 else:assert error=='non-nested C ABI stack' and not (folder/'context-audit.json').exists()
 return dict(execution=e,context_error=error,context_audit=audit,raw_events=len(records),thread_ledger=ledger)


for case in cases:
 tag=case['tag'];zpath=base/(tag+'.zip');artifact=case['artifacts'][0]
 assert hashlib.sha256(zpath.read_bytes()).hexdigest()==artifact['digest'].removeprefix('sha256:')
 dest=base/('audit-'+tag)
 with zipfile.ZipFile(zpath) as z:
  assert z.testzip() is None and all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in z.namelist());z.extractall(dest)
 exp=dest/'experiment';m=json.loads((exp/'experiment.json').read_text());out={'source_sha':case['source_sha'],'checkout_sha':case['checkout_sha'],'original_status':m['status'],'manifest':m}
 if tag in ('initial','fixed'):
  e=json.loads((exp/'control/execution.json').read_text());stderr=(exp/'control/bpftrace-stderr.log').read_text()
  assert m['status']=='failed' and m['stages']==[] and e['exit_code']==255 and not e['timed_out'] and not e['cleanup_signals'] and e['group_gone']
  assert not (exp/'qualification').exists() and not (exp/'control/events.log').read_text().strip()
  if tag=='initial':assert "path 'exec' does not exist" in stderr
  else:assert 'compiled without (k|u)probe offset support' in stderr
  out['blocked_before_control']={'stderr':stderr,'execution':e,'native_business_windows':0}
 else:
  assert (dest/'tracer-source.txt').read_text().strip()=='93c593f6dab2e930d6198cfaa52b29d19a8c0647'
  info=(dest/'bpftrace-info.txt').read_text();assert 'bfd: yes' in info and 'unsafe probe: no' in info and 'version: v0.21.2' in info
  cache=(dest/'tracer-CMakeCache.txt').read_text();assert re.search(r'ALLOW_UNSAFE_PROBE:[^=]+=OFF',cache)
  hashes={line.split()[1]:line.split()[0] for line in (dest/'binary-sha256.txt').read_text().splitlines()}
  ctrl=stage(exp/'control',hashes['bin/ret-control'],True);values=json.loads((exp/'control/native-stdout.log').read_text());call=ctrl['context_audit']['mmap_calls']
  assert len(call)==1 and call[0]['observed_contexts']==[1] and call[0]['successful'] and call[0]['size']==1048576 and call[0]['value']==values['address'] and values['touched_pages']==256 and values['checksum']==1792
  out['control']=ctrl
  q=exp/'qualification';qstage=stage(q,hashes['bin/probe'],tag=='tail');r=json.loads((q/'native/report.json').read_text())
  assert case['checkout_sha'] in r['build_info'] and 'vcs.modified=false' in r['build_info'] and r['build_info']==m['description']['build_info']
  assert (r['transport'],r['mode'],r['settings']['duration_seconds'],r['settings']['warmup_seconds'],r['settings']['pool_min'],r['settings']['pool_max'],r['settings']['workers'],r['settings']['qps'])==(3,1,15,12,16,64,2,10)
  assert r['settings']['pid']==qstage['execution']['target_identity']['pid']
  acceptance=v.validate_report(r,True);events=v.validate_events(q/'native/exchanges.jsonl.gz',r);v.validate_engine_logs(q/'native',q/'native-stderr.log',64,3)
  qstage.update(native_acceptance=acceptance,audited_events=events,counts=r['counts'])
  if tag=='build':assert m['status']=='failed' and m['error']=='ValueError: non-nested C ABI stack'
  else:
   assert m['status']=='pilot_passed' and m['stages']==['control_passed'] and events==m['audited_events'] and acceptance==m['acceptance'] and canon(qstage['context_audit'])==m['context_audit']
   groups={}
   for call in qstage['context_audit']['mmap_calls']:
    key=str(call['observed_contexts']);g=groups.setdefault(key,dict(calls=0,successful=0,cumulative_successful_virtual_bytes=0))
    g['calls']+=1
    if call['successful']:g['successful']+=1;g['cumulative_successful_virtual_bytes']+=call['size']
   qstage['mapping_context_groups']=groups
  out['qualification']=qstage
 result[tag]=out
 print(tag,m['status'],out.get('qualification',{}).get('native_acceptance'),out.get('qualification',{}).get('context_error'))
 if tag=='tail':print('CONTEXTS',out['qualification']['mapping_context_groups']);print('PAIRS',out['qualification']['context_audit']['matched_pairs_by_kind'],'TAIL',out['qualification']['context_audit']['matched_tail_exits_by_kind'])
(base/'independent-audit.json').write_text(json.dumps(result,indent=2)+'\n')
