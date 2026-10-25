#!/usr/bin/env python3
"""Validate recorded release gates against exact tracked build/document inputs."""
import argparse,hashlib,json,subprocess
from pathlib import Path

REQUIRED={'regression','packaging','supported_matrix_10x','lifecycle_100','soak_24h','native_platforms','integration_review'}
EXCLUDED={'docs/release-gates.json','docs/integration-readiness.md'}
def fingerprint(root):
 paths=subprocess.check_output(['git','ls-files','-z'],cwd=root).decode().strip('\0').split('\0');h=hashlib.sha256()
 for name in sorted(paths):
  if name in EXCLUDED or name.startswith('docs/evidence/integration/'):continue
  h.update(name.encode()+b'\0');h.update(hashlib.sha256((root/name).read_bytes()).digest())
 return h.hexdigest()
def evaluate(policy,current):
 gates=policy.get('gates',[]);ids=[g.get('id') for g in gates]
 if len(ids)!=len(set(ids)) or set(ids)!=REQUIRED:raise ValueError('release policy must retain every required gate exactly once')
 if any(g.get('status') not in ('passed','pending','failed') for g in gates):raise ValueError('invalid gate status')
 if any(g['status']=='passed' and not g.get('evidence') for g in gates):raise ValueError('passed gate requires evidence')
 blockers=[g['id'] for g in gates if g['status']!='passed']
 if policy.get('verified_input_sha256')!=current:blockers.append('input_fingerprint')
 return {'release_ready':not blockers,'input_sha256':current,'blockers':blockers}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--report',action='store_true');p.add_argument('--policy',type=Path,default=Path('docs/release-gates.json'));a=p.parse_args();root=Path(__file__).resolve().parents[1]
 policy=json.loads((root/a.policy).read_text());report=evaluate(policy,fingerprint(root));print(json.dumps(report,indent=2))
 if not a.report and not report['release_ready']:raise SystemExit(1)
if __name__=='__main__':main()
