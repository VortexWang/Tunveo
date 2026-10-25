#!/usr/bin/env python3
"""Compare default/explicit identity behavior against the immutable pre-fix engine."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

BEFORE = '6cff6b1cb61005ea8227d1b5c4bb9ed252ab6263'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--go', required=True)
    p.add_argument('--artifacts', type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    dest = a.artifacts.resolve()
    dest.mkdir(parents=True, exist_ok=False)
    results = []
    report = {'before_commit': BEFORE, 'scope': 'new/new real process comparison; two identities, four transports and two flows; expired leaves signed by a valid trust root', 'results': results}
    try:
        with tempfile.TemporaryDirectory(prefix='tunveo-identity-before-') as temp:
            folder = Path(temp)
            raw = subprocess.check_output(['git', 'archive', BEFORE], cwd=root)
            with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
                tar.extractall(folder, filter='data')
            before = folder/'tunveo-before'
            subprocess.run([a.go, 'build', '-trimpath', '-o', str(before), './cmd/tunveo'], cwd=folder, env=dict(os.environ, GOTOOLCHAIN='local'), check=True, timeout=240)
            report['before_archive_sha256'] = hashlib.sha256(raw).hexdigest()
            report['before_binary_sha256'] = hashlib.sha256(before.read_bytes()).hexdigest()
            for identity in ('default-ip', 'explicit-dns'):
                for stage, binary, negative in [('before', before, None), ('after', a.binary.resolve(), None), ('expired', a.binary.resolve(), 'expired')]:
                    name = stage+'-'+identity
                    args = [sys.executable, str(root/'scripts/verify_forwarding.py'), '--binary', str(binary), '--tls', '2', '--identity', identity, '--go', a.go, '--artifacts', str(dest/name)]
                    if negative:
                        args += ['--reject-tls', negative, '--io-timeout', '.5']
                    with (dest/(name+'.console.txt')).open('w') as log:
                        run = subprocess.run(args, cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=180)
                    r = json.loads((dest/name/'report.json').read_text())
                    failed = {(x['transport'], x['mode']) for x in r['results'] if x['status'] != 'passed'}
                    expected = {(t,m) for t in ((0,1,3) if identity=='default-ip' else (2,)) for m in (1,2)} if stage=='before' else set()
                    assert len(r['results'])==8 and failed==expected, (name, failed, expected)
                    assert run.returncode == (1 if stage=='before' else 0), name
                    assert all(x.get('failed_phase')=='pool_ready' for x in r['results'] if x['status']!='passed'), name
                    assert all(c['reaped'] and not c['forced_kill'] for x in r['results'] for c in x['cleanup']), name
                    results.append({'scenario': name, 'status': 'reproduced' if stage=='before' else 'passed', 'passed':8-len(failed), 'failed':len(failed), 'report':name+'/report.json'})
            report['status'] = 'passed'
    except BaseException as e:
        report.update(status='failed', error_type=type(e).__name__, error=str(e))
        raise
    finally:
        (dest/'identity-summary.json').write_text(json.dumps(report,indent=2)+'\n')
        print('IDENTITY_SUMMARY='+json.dumps(report))


if __name__=='__main__':main()
