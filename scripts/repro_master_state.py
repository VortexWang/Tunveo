#!/usr/bin/env python3
"""Run actual master state concurrency paths from an unmodified git archive."""
import argparse,hashlib,io,json,os,subprocess,tarfile,tempfile
from pathlib import Path

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--ref',required=True);p.add_argument('--mode',choices=['original','fixed'],required=True);p.add_argument('--go',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();root=Path(__file__).resolve().parents[1]
 commit=subprocess.check_output(['git','rev-parse',a.ref],cwd=root,text=True).strip();template=(root/'internal/master/state_concurrency_test.go').read_bytes();archive=subprocess.check_output(['git','archive',commit],cwd=root)
 with tempfile.TemporaryDirectory(prefix='tunveo-state-') as temp:
  folder=Path(temp)
  with tarfile.open(fileobj=io.BytesIO(archive)) as tar:tar.extractall(folder,filter='data')
  test=template.decode().replace('var expectStateSnapshotFailure = false','var expectStateSnapshotFailure = '+('true' if a.mode=='original' else 'false'))
  (folder/'internal/master/state_concurrency_test.go').write_text(test)
  run=subprocess.run([a.go,'test','-race','-count=1','-timeout=60s','-v','-run','^Test(InstanceLogAndManagementSerialization|QueuedInstanceEventIsSnapshot)$','./internal/master'],cwd=folder,env=dict(os.environ,GOTOOLCHAIN='local'),capture_output=True,text=True,timeout=90)
 race='DATA RACE' in run.stdout+run.stderr
 ok=(run.returncode!=0 and race and 'REPRODUCED-SNAPSHOT:' in run.stdout) if a.mode=='original' else (run.returncode==0 and not race and 'PASSED-SNAPSHOT:' in run.stdout)
 report={'source_commit':commit,'mode':a.mode,'status':('reproduced' if a.mode=='original' else 'passed') if ok else 'failed','runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'template_sha256':hashlib.sha256(template).hexdigest(),'scope':'native production log writer, REST PATCH/GET, GOB and queued event JSON; synthetic instance, no child process; test expectation flag only differs','test_exit_code':run.returncode,'race_observed':race,'stdout':run.stdout,'stderr':run.stderr}
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['source_commit','status','race_observed','test_exit_code']}))
 if not ok:raise SystemExit(1)
if __name__=='__main__':main()
