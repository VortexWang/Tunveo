#!/usr/bin/env python3
"""Run the same real TLS admission template against immutable before/fixed source."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ref', required=True)
    p.add_argument('--mode', choices=('original', 'fixed'), required=True)
    p.add_argument('--go', required=True)
    p.add_argument('--repeat', type=int, default=10)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if not 1 <= a.repeat <= 100:
        p.error('repeat must be 1..100')
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(['git', 'rev-parse', a.ref], cwd=root, text=True).strip()
    archive = subprocess.check_output(['git', 'archive', commit], cwd=root)
    template = (root / 'internal/tunnelpool/websocket/dial_limit_test.go').read_bytes()
    with tempfile.TemporaryDirectory(prefix='tunveo-ws-dial-') as folder:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(folder, filter='data')
        (Path(folder) / 'internal/tunnelpool/websocket/dial_limit_test.go').write_bytes(template)
        run = subprocess.run([a.go, 'test', '-race', '-count=' + str(a.repeat), '-run',
                              '^TestClientManagerBoundsConcurrentDials$', '-v', './internal/tunnelpool/websocket'],
                             cwd=folder, capture_output=True, text=True, timeout=180)
    passed = run.stdout.count('--- PASS: TestClientManagerBoundsConcurrentDials')
    failed = run.stdout.count('--- FAIL: TestClientManagerBoundsConcurrentDials')
    valid = 'DATA RACE' not in run.stdout + run.stderr
    if a.mode == 'original':
        valid = valid and run.returncode == 1 and failed == a.repeat and passed == 0 and run.stdout.count('DIAL-LIMIT: fifth simultaneous TLS request') == a.repeat
    else:
        valid = valid and run.returncode == 0 and passed == a.repeat and failed == 0
    report = dict(status='passed' if valid else 'failed', mode=a.mode, source_commit=commit,
                  template_sha256=hashlib.sha256(template).hexdigest(), archive_sha256=hashlib.sha256(archive).hexdigest(),
                  repeat=a.repeat, passed=passed, failed=failed, exit_code=run.returncode,
                  stdout=run.stdout, stderr=run.stderr,
                  scope='controlled pre-upgrade TLS gate; maximum simultaneous dials and full deficit attempts, not historical spike attribution or performance')
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k not in ('stdout', 'stderr')}))
    return 0 if valid else 1


if __name__ == '__main__':
    raise SystemExit(main())
