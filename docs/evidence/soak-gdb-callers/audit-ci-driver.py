"""Run at repository root with both original ZIPs and their metadata in artifacts/gdb-callers."""
import json,hashlib,zipfile,sys
from pathlib import Path
sys.path.insert(0,'scripts')
import soak_gdb_callers as callers
import soak_mappings as mappings
import verify_soak as verify
base=Path('artifacts/gdb-callers');all_results={}
for tag in ('initial','fixed'):
 metadata=base/(tag+'-ci-metadata.json')
 if not metadata.exists():continue
 meta=json.loads(metadata.read_text());artifact=meta['artifacts'][0];zpath=base/(artifact['name']+'-'+tag+'.zip')
 assert hashlib.sha256(zpath.read_bytes()).hexdigest()==artifact['digest'].removeprefix('sha256:')
 dest=base/('audit-'+tag)
 with zipfile.ZipFile(zpath) as z:
  assert z.testzip() is None
  assert all(not Path(p).is_absolute() and '..' not in Path(p).parts for p in z.namelist())
  z.extractall(dest)
 exp=dest/'experiment';manifest=json.loads((exp/'experiment.json').read_text());out={'source_sha':meta['source_sha'],'checkout_sha':meta['checkout_sha'],'manifest':manifest}
 assert meta['checkout_sha'] in manifest['description']['build_info'] and 'vcs.modified=false' in manifest['description']['build_info']
 assert manifest['pilot_only'] and manifest['traced_duration_seconds']==60 and manifest['untraced_duration_seconds']==180
 control=callers.read_calls(exp/'control');stored=json.loads((exp/'control/caller-audit.json').read_text());assert all(stored[k]==v for k,v in control.items());raw=json.loads((exp/'control/native-stdout.log').read_text())
 assert len(control['rows'])==1 and control['rows'][0]['successful'] and control['rows'][0]['address']==raw['address'] and control['rows'][0]['size']==raw['size']==1048576
 assert raw['touched_pages']==256 and raw['checksum']==1792
 assert all(x in control['rows'][0]['backtrace'] for x in ('control_mmap','control_parent','main'))
 out['control']=control
 traced=exp/'traced';state=json.loads((traced/'gdb-result.json').read_text()) if (traced/'gdb-result.json').exists() else None
 if state is not None and state['exit_code']==0:
  c=callers.read_calls(traced);stored=json.loads((traced/'caller-audit.json').read_text());assert all(stored[k]==v for k,v in c.items());assert stored['gdb_exit_code']==0
  r=json.loads((traced/'native/report.json').read_text());assert r['build_info']==manifest['description']['build_info']
  config=json.loads((traced/'gdb-config.json').read_text());assert config['binary_sha256']==manifest['binary_sha256']
  assert config['inferior_arguments']==['--transport','3','--mode','1','--duration','60s','--warmup','12s','--sample-interval','5s','--workers','2','--qps','10','--pool-min','16','--pool-max','64','--artifacts',config['inferior_arguments'][-1]]
  assert config['run_command']==callers.run_command(config['inferior_arguments'],Path(config['inferior_arguments'][-1]).parent)
  for line in (traced/'mmap-calls.jsonl').read_text().splitlines():assert json.loads(line)['inferior_pid']==r['settings']['pid']
  events=verify.validate_events(traced/'native/exchanges.jsonl.gz',r)
  verify.validate_engine_logs(traced/'native',traced/'native-stderr.log',64,3)
  try:acceptance=verify.validate_report(r,True);error=None
  except ValueError as exc:acceptance=None;error=str(exc)
  assert manifest.get('traced_acceptance')==acceptance and manifest.get('traced_acceptance_error')==error
  assert events==manifest['traced_events']
  out['traced']={'complete_native_execution':True,'callers':c,'acceptance':acceptance,'acceptance_error':error,'events':events,'counts':r['counts']}
 else:
  # Failed execution remains failed. Validate partial entry/returns separately,
  # without modifying raw files or relaxing the production audit's exit guard.
  records=[json.loads(x) for x in (traced/'mmap-calls.jsonl').read_text().splitlines()]
  entries={x['id']:x for x in records if x['event']=='entry'};returns={x['id']:x for x in records if x['event']=='return'}
  assert len(records)==len(entries)+len(returns)
  if state is not None:assert len(entries)==state['entry_calls'] and len(returns)==state['returns']
  for key,r in returns.items():
   e=entries[key];assert (r['inferior_pid'],r['thread_ptid'])==(e['inferior_pid'],e['thread_ptid']) and r['at_unix_ns']>=e['at_unix_ns']
  if state is not None:
   assert state['exit_code']==2 and (traced/'native-stderr.log').read_text().strip()=='invalid soak settings'
   assert not (traced/'native/report.json').exists() and manifest['errors']==['ValueError: incomplete GDB execution']
   out['traced']={'complete_native_execution':False,'gdb_state':state,'partial_entries':len(entries),'partial_entry_returns':len(returns),'scope':'startup calls only; no 60s load or business coverage; original failure retained'}
  else:
   assert len(manifest['errors'])==1 and manifest['errors'][0].startswith('TimeoutExpired:')
   config=json.loads((traced/'gdb-config.json').read_text());assert config['binary_sha256']==manifest['binary_sha256']
   assert config['run_command']==callers.run_command(config['inferior_arguments'],Path(config['inferior_arguments'][-1]).parent)
   r=json.loads((traced/'native/report.json').read_text());assert r['status']=='running' and not r['points'] and r['measured_seconds']==0
   assert all(v==0 for v in r['counts'].values()) and all(v==0 for v in r['warmup_counts'].values())
   assert len({x['inferior_pid'] for x in records})==1 and all(x['thread_ptid'][0]==x['inferior_pid'] for x in records)
   assert 'pid' not in r['settings']  # startup checkpoint precedes PID registration
   out['traced']={'complete_native_execution':False,'gdb_result_missing':True,'partial_entries':len(entries),'partial_entry_returns':len(returns),'last_minus_first_record_seconds':(records[-1]['at_unix_ns']-records[0]['at_unix_ns'])/1e9,'native_report_status':'running','native_measured_seconds':0,'scope':'360s timeout, no warmup/measured points or business coverage; no proof of tracer/inferior cleanup or observer-free host isolation before next window'}
 u=mappings.audit(exp/'untraced-180');assert u==manifest['untraced_audit'];out['untraced']=u
 s=json.loads((exp/'untraced-180/pilot/summary.json').read_text());assert s['binary_sha256']==manifest['binary_sha256']
 assert manifest['status']==('failed' if manifest['untraced_exit_code'] or manifest['errors'] else 'pilot_passed')
 out['scope']='function-entry/return observations and independently audited original pilots; no complete unmap/reuse ledger or resident attribution'
 all_results[tag]=out
 print(tag,'control matched 1MiB entry/return and 3 caller names; traced complete:',out['traced']['complete_native_execution'])
 if out['traced']['complete_native_execution']:
  t=out['traced'];print('traced acceptance:',t['acceptance'],t['acceptance_error'],'events:',t['events']);print('caller groups:',t['callers']['groups']);print('entry/return:',t['callers']['gdb_state'])
  for category in t['callers']['groups']:
   print('SAMPLE',category);print(next(x['backtrace'] for x in t['callers']['rows'] if x['caller_category']==category))
 print('untraced:',u['status'],u['error'],'RSSgrowthMiB',u['statm_rss_delta']/1048576,'events',u['audited_events'])
(base/'independent-audit.json').write_text(json.dumps(all_results,indent=2)+'\n')
