from pathlib import Path
import sys,json,hashlib
root=Path('/workspace/scratch/0db146b59a43/Tunveo');sys.path.insert(0,str(root/'scripts'));import verify_soak as v;import soak_mappings as m;import audit_soak_retention as a;import audit_soak_os_memory as os
base=root/'artifacts/post-stop-retention';out={}
for mode in ('ordinary','race'):
 d=base/f'local-{mode}';s=json.loads((d/'summary.json').read_text());r=json.loads((d/'native/report.json').read_text())
 for f,sha in s['files'].items():assert hashlib.sha256((d/f).read_bytes()).hexdigest()==sha
 assert s['exit_code']==0 and s['cleanup']['reaped'] and not s['cleanup']['forced_kill'] and s['pilot'] and not s['qualifies_24h']
 assert '0d2b8eb2e7542e7f4406f72687afc8403b466db2' in r['build_info'] and 'vcs.modified=false' in r['build_info']
 error=None
 try:v.validate_report(r,True)
 except ValueError as e:error='ValueError: '+str(e)
 assert (s['status']=='pilot_passed')==(error is None) and s.get('error')==error
 events=v.validate_events(d/'native/exchanges.jsonl.gz',r);v.validate_engine_logs(d/'native',d/'stderr.log',64,3)
 gc,forced=a.validate_retention_points(r)
 for p in r['post_stop_observation']:
  mm=p['resources']['os_memory'];assert not mm.get('error') and os.parse_rollup(mm['smaps_rollup_raw'])==mm['bytes']
 seals=json.loads((base/f'local-{mode}-load-seals.json').read_text());frozen=m.load_evidence_hash(r)
 for seal in seals:
  assert seal['load_evidence_sha256']==frozen
  p=next(p for p in r['post_stop_observation'] if m.point_key(p)==m.point_key(seal))
  assert hashlib.sha256(json.dumps(p,sort_keys=True,separators=(',',':')).encode()).hexdigest()==seal['point_sha256']
 selected=[dict(phase=p['phase'],at_seconds=p['at_seconds'],**{k:p['resources'][k] for k in ('rss','heap_alloc','heap_released','heap_sys')}) for p in [gc[0],gc[-1]]+forced]
 out[mode]={'active_acceptance':s['status'],'active_error':error,'audited_events':events,'counts':r['counts'],'original_load':os.audit(d/'native/report.json'),'post_stop_selected':selected,'self_rollups_verified':len(r['post_stop_observation']),'load_hash_seals_verified':len(seals),'first_seal_at_seconds':seals[0]['at_seconds'],'scope':'native self measurements only; JSON-only monitor started mid post-stop window,15 seals cover later checkpoints only; no external smaps or PID access attempted; original failure unchanged'}
 print(mode,s['status'],'RSSdelta',out[mode]['original_load']['statm_rss_delta']/1048576,'events',events,'postRSS',[round(p['rss']/1048576,5) for p in selected],'seals',len(seals))
(base/'local-audit.json').write_text(json.dumps(out,indent=2)+'\n')
