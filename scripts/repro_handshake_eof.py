#!/usr/bin/env python3
"""Hold the HTTPS handler after completion publication, using an isolated archive."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ref', required=True)
    p.add_argument('--mode', choices=('original', 'fixed'), required=True)
    p.add_argument('--repeat', type=int, default=10)
    p.add_argument('--go', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(['git', 'rev-parse', a.ref], cwd=root, text=True).strip()
    template = (root/'scripts/fixtures/handshake_publish_test.go.txt').read_bytes()
    with tempfile.TemporaryDirectory(prefix='tunveo-handshake-eof-') as temp:
        folder = Path(temp)
        archive = subprocess.check_output(['git', 'archive', commit], cwd=root)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(folder, filter='data')
        source = folder/'internal/server/handshake.go'
        original = source.read_bytes()
        anchor = '\t\t\tclose(done)'
        text = original.decode()
        assert text.count(anchor) == 1, 'completion anchor changed'
        text = text.replace(anchor, anchor+'\n\t\t\thandshakePublishHook()')
        text += '\nvar handshakePublishHook = func() {}\n'
        source.write_text(text)
        module = (folder/'go.mod').read_text().splitlines()[0].split()[1]
        common_value = '&base' if '*common.Common' in (source.parent/'server.go').read_text() else 'base'
        fixture = template.decode().replace('MODULE', module).replace('COMMON_VALUE', common_value)
        fixture += '\nconst expectHandshakeEOF = '+('true' if a.mode=='original' else 'false')+'\n'
        (source.parent/'handshake_publish_test.go').write_text(fixture)
        run = subprocess.run([a.go,'test','-race','-v','-count',str(a.repeat),'-run','^TestHandshakeCloseBeforeHandlerReturn$','./internal/server'],cwd=folder,env=dict(os.environ,GOTOOLCHAIN='local'),capture_output=True,text=True,timeout=240)
    marker = 'REPRODUCED:' if a.mode=='original' else 'PASSED:'
    observed = run.stdout.count(marker)
    report = {'source_commit':commit,'mode':a.mode,'scope':'test-only barrier after close(done), real HTTPS; establishes a possible EOF cause, not attribution of historical random failures','source_sha256':hashlib.sha256(original).hexdigest(),'instrumented_sha256':hashlib.sha256(text.encode()).hexdigest(),'template_sha256':hashlib.sha256(template).hexdigest(),'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'repeat':a.repeat,'observed':observed,'test_exit_code':run.returncode,'stdout':run.stdout,'stderr':run.stderr}
    report['status'] = ('reproduced' if a.mode=='original' else 'passed') if run.returncode==0 and observed==a.repeat else 'failed'
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('mode','status','observed')}))
    if report['status']=='failed':raise SystemExit(1)


if __name__=='__main__':main()
