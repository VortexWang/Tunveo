"""Run from repository root after placing original CI ZIPs and ci-metadata.json here."""
from pathlib import Path
import sys,json,zipfile,hashlib
sys.path.insert(0,'scripts')
import soak_thp as thp
base=Path('artifacts/thp-control')
metadata=json.loads((base/'ci-metadata.json').read_text())
all_cases={}
for artifact in metadata['artifacts']:
 name=artifact['name'];path=base/(name+'.zip')
 digest=hashlib.sha256(path.read_bytes()).hexdigest()
 assert digest==artifact['digest'].removeprefix('sha256:')
 dest=base/name
 with zipfile.ZipFile(path) as z:
  assert z.testzip() is None
  assert all(not Path(f).is_absolute() and '..' not in Path(f).parts for f in z.namelist())
  z.extractall(dest)
 official=json.loads((base/'official-runtime-source.json').read_text())
 for key,filename in [('mem_linux_go','runtime-mem_linux.go.txt'),('extern_go','runtime-extern.go.txt')]:
  assert hashlib.sha256((dest/filename).read_bytes()).hexdigest()==official[key]['sha256']
 exp=dest/'experiment';m=json.loads((exp/'experiment.json').read_text())
 assert len(m['arms'])==2 and {a['policy'] for a in m['arms']}=={'default','disablethp'}
 assert [a['policy'] for a in m['arms']]==m['order']
 assert 'vcs.modified=false' in m['description']['build_info']
 assert metadata['checkout_sha'] in m['description']['build_info']
 assert m['pilot_only'] and not m['host_policy_written']
 cases=[]
 for arm in m['arms']:
  policy=arm['policy'];expected=dict(m['inherited_runtime_environment']);expected['GODEBUG']='disablethp=1' if policy=='disablethp' else None
  assert arm['expected_runtime_environment']==expected
  # Fresh rerun from raw, disregarding stored computed audit as authority.
  audit=thp.audit_arm(exp/policy,policy,expected,m['binary_sha256'])
  assert audit==arm['audit']==json.loads((exp/(policy+'-audit.json')).read_text())
  r=json.loads((exp/policy/'pilot/native/report.json').read_text())
  assert r['counts']['tcp']==1350 and r['counts']['udp']==450 and not r['counts']['failed'] and not r['counts']['dropped']
  rows=audit['series'];gc=[p for p in rows if p['phase']=='poststop_gc'];force=[p for p in rows if p['phase']=='poststop_go_scavenge'];assert len(force)==1
  host=[]
  for stage in ('host_before','host_after'):
   files=arm[stage]['files'];host.append({p:files.get('/sys/kernel/mm/transparent_hugepage/'+p) for p in ('enabled','defrag','khugepaged/max_ptes_none')})
  cases.append(dict(policy=policy,binary_sha256=m['binary_sha256'],active_acceptance=audit['retention']['active_acceptance'],active_error=audit['retention']['active_error'],active_rss_delta=audit['retention']['active_rss_delta'],counts=r['counts'],audited_events=audit['retention']['audited_events'],selected=[gc[0],gc[-1],force[0]],all_heap_no_hugepage=all(x['go_heap']['all_no_hugepage'] for x in rows),max_heap_anon_huge_pages=max(x['go_heap']['anon_huge_pages'] for x in rows),final_groups_rss=audit['retention']['selected'][-1]['groups_rss_bytes'],host_selected_policies=host,selected_host_policies_equal=host[0]==host[1]))
 all_cases[name]=dict(order=m['order'],driver_status=m['status'],cases=cases,go_runtime_source_hashes=(dest/'runtime-source.sha256').read_text())
result=dict(source_sha=metadata['source_sha'],checkout_sha=metadata['checkout_sha'],cases=all_cases,scope='8 one-attempt pilots; same binary within each pair, separate processes; selected policy snapshots do not establish all host state constant; original resource failures retained')
(base/'independent-audit.json').write_text(json.dumps(result,indent=2)+'\n')
for name,pair in all_cases.items():
 print(name)
 for c in pair['cases']:
  print(c['policy'],c['active_acceptance'],'activeMiB',c['active_rss_delta']/1048576,'postStopRSS',[round(x['statm_rss']/1048576,4) for x in c['selected']],'heapRSS',[round(x['go_heap']['rss']/1048576,4) for x in c['selected']],'heapAHP',[x['go_heap']['anon_huge_pages']/1048576 for x in c['selected']])
