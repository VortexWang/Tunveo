"""Run from repository root; original ZIPs and metadata live in artifacts/mapping-ledger."""
import gzip,hashlib,importlib.util,json,re,subprocess,sys,zipfile
from pathlib import Path
sys.path.insert(0,'scripts')
import soak_mapping_ledger as ledger
import soak_ret_context as context
import verify_soak as verify
import audit_soak_os_memory as rollup
base=Path('artifacts/mapping-ledger');cases=json.loads((base/'ci-metadata.json').read_text());out={}
canon=lambda x:json.loads(json.dumps(x))


def cleanup(folder):
 e=json.loads((folder/'execution.json').read_text());target=context.proc_identity((folder/'target-before.stat').read_text());parent=context.proc_identity((folder/'tracer-before.stat').read_text())
 assert e['exit_code']==0 and not e['timed_out'] and not e['cleanup_signals'] and e['target_identity_verified'] and e['group_gone']
 assert target==e['target_identity'] and parent==e['tracer_identity']
 assert context.owned_groups(e['process_group'],target,parent,(folder/'tracer-exe.txt').read_text(),Path(e['command'][2]))==e['owned_groups']
 assert not re.search(r'(?i)lost|dropped|error|failed',(folder/'bpftrace-stderr.log').read_text())
 return e


def memory_stage(folder,race,control=False):
 e=cleanup(folder);p=json.loads((folder/'plan.json').read_text());symbols=ledger.CONTROL if control else context.SYMBOLS
 assert {k:f['symbol'] for k,f in p['functions'].items()}=={str(k):v for k,v in symbols.items()}
 for kind,f in p['functions'].items():
  assert context.ret_sites(f['disassembly'],f['address'],f['size'])==f['ret_offsets']
  tails=f.get('tail_exits',[])
  assert not tails or (kind=='1' and all(t['symbol']=='_ZN6__tsan10SlotUnlockEPNS_11ThreadStateE' for t in tails))
  assert context.tail_sites(f['disassembly'],f['address'],f['size'],{t['target']:t['symbol'] for t in tails})==tails
 parsed=ledger.parse((folder/'events.log').read_text(),p,e['expected_uid'])
 assert canon(parsed)==json.loads((folder/'context-audit.json').read_text())
 rows=ledger.audit_snapshots(folder,parsed,race,control)
 result=dict(execution=e,ledger=parsed,snapshots=rows)
 if not control:
  # This is a second, explicitly coarser question: all known observed symbols
  # belong to the pinned Go race runtime. Preserve generations, failed calls,
  # concurrency and in-flight rejection; never relabel an empty context.
  family=ledger.prepare([dict(c,owner='observed_race_runtime' if c['contexts'] else 'unresolved') for c in parsed['calls']])
  capture=json.loads((folder/'snapshots.json').read_text());broad=[]
  for rec in capture['records']:
   raw=gzip.open(folder/rec['file'],'rt').read();a=ledger.attribute(raw,True,family,rec['read_start_monotonic_ns'],rec['read_end_monotonic_ns'])
   broad.append(dict(key=rec['key'],**a))
  for fine,coarse in zip(rows,broad):assert sum(fine['groups_rss_bytes'].values())==sum(coarse['groups_rss_bytes'].values())
  raw_rollup=rollup.audit(folder/'native/report.json')
  r=json.loads((folder/'native/report.json').read_text());acceptance=verify.validate_report(r,True);events=verify.validate_events(folder/'native/exchanges.jsonl.gz',r);verify.validate_engine_logs(folder/'native',folder/'native-stderr.log',64,3)
  assert (r['transport'],r['mode'],r['settings']['duration_seconds'],r['settings']['warmup_seconds'],r['settings']['pool_min'],r['settings']['pool_max'],r['settings']['workers'],r['settings']['qps'])==(3,1,15,12,16,64,2,10)
  assert r['settings']['pid']==parsed['native_pid']==e['target_identity']['pid']
  warm=[p for p in r['points'] if p['phase']=='warmup' and p['at_seconds']>=6];steady=[p for p in r['points'] if p['phase']=='measured'];b=max(warm,key=lambda p:p['resources']['rss']);peak=max(steady,key=lambda p:p['resources']['rss'])
  indices={tuple(x['key']):i for i,x in enumerate(rows)};bi=indices[(b['phase'],b['at_seconds'])];pi=indices[(peak['phase'],peak['at_seconds'])]
  assert raw_rollup['statm_rss_delta']==peak['resources']['rss']-b['resources']['rss']
  result.update(rollup_audit=raw_rollup,acceptance=acceptance,events=events,counts=r['counts'],coarse_runtime=broad,
    budget_envelope=dict(baseline_at_seconds=b['at_seconds'],peak_at_seconds=peak['at_seconds'],baseline_rss=b['resources']['rss'],peak_rss=peak['resources']['rss'],active_rss_delta=peak['resources']['rss']-b['resources']['rss'],measured_first_last_rss_delta=acceptance['resource_trend']['rss']),
    selected=dict(baseline_fine=rows[bi],peak_fine=rows[pi],baseline_coarse=broad[bi],peak_coarse=broad[pi]),
    scope='same captured process; whole-VMA request-origin lower bounds. Coarse family does not identify individual objects or prorate fine mixed regions; separate statm/smaps reads are not atomic')
 return result


for meta in cases:
 tag=meta['tag'];zpath=base/(tag+'.zip');artifact=meta['artifacts'][0]
 assert hashlib.sha256(zpath.read_bytes()).hexdigest()==artifact['digest'].removeprefix('sha256:')
 dest=base/('audit-'+tag)
 with zipfile.ZipFile(zpath) as z:
  assert z.testzip() is None and all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in z.namelist());z.extractall(dest)
 for key in ('source_sha','checkout_sha'):assert subprocess.check_output(['git','rev-parse',meta[key]+'^{tree}'],text=True).strip()==meta['tree_sha']
 assert (dest/'tracer-source.txt').read_text().strip()=='93c593f6dab2e930d6198cfaa52b29d19a8c0647'
 info=(dest/'bpftrace-info.txt').read_text();assert 'version: v0.21.2' in info and 'bfd: yes' in info and 'unsafe probe: no' in info
 exp=dest/'experiment';m=json.loads((exp/'experiment.json').read_text());control=memory_stage(exp/'control',False,True);pilot=memory_stage(exp/'pilot',True)
 hashes={line.split()[1]:line.split()[0] for line in (dest/'binary-sha256.txt').read_text().splitlines()}
 assert json.loads((exp/'control/plan.json').read_text())['binary_sha256']==hashes['bin/ledger-control']
 assert json.loads((exp/'pilot/plan.json').read_text())['binary_sha256']==hashes['bin/probe']
 r=json.loads((exp/'pilot/native/report.json').read_text());assert meta['checkout_sha'] in r['build_info'] and 'vcs.modified=false' in r['build_info']
 assert canon(control['ledger'])==m['control']['ledger'] and canon(control['snapshots'])==m['control']['snapshots']
 if tag=='initial':
  assert m['status']=='failed' and m['error']=='ValueError: native point changed'
  # Freeze the old auditor to reproduce its actual failure on the SAME ZIP.
  frozen=base/'initial-auditor-frozen.py';frozen.write_bytes(subprocess.check_output(['git','show',meta['source_sha']+':scripts/soak_mapping_ledger.py']))
  spec=importlib.util.spec_from_file_location('frozen_ledger_auditor',frozen);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  try:module.audit_snapshots(exp/'pilot',pilot['ledger'],True)
  except ValueError as error:assert str(error)=='native point changed'
  else:raise AssertionError('old failure disappeared')
 else:
  assert m['status']=='pilot_passed' and m['description']['build_info']==r['build_info'] and m['events']==pilot['events'] and m['acceptance']==pilot['acceptance']
  assert canon(pilot['ledger'])==m['pilot']['ledger'] and canon(pilot['snapshots'])==m['pilot']['snapshots']
 out[tag]=dict(metadata=meta,original_status=m['status'],control=control,pilot=pilot)
 print(tag,'original status',m['status'],'core business',pilot['counts'],'events',pilot['events'],'active RSS growthMiB',pilot['budget_envelope']['active_rss_delta']/1048576,'measured trendMiB',pilot['budget_envelope']['measured_first_last_rss_delta']/1048576)
 print('selected peak coarse',pilot['selected']['peak_coarse']['groups_rss_bytes'])
(base/'independent-audit.json').write_text(json.dumps(out,indent=2)+'\n')
