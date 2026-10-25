#!/usr/bin/env python3
"""Run uninstrumented native HTTP/2 deadline regressions against a git archive."""
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ref', required=True)
    parser.add_argument('--mode', choices=['original', 'fixed'], required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--repeat', type=int, default=10)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(['git', 'rev-parse', args.ref], cwd=root, text=True).strip()
    template = (root / 'internal/tunnelpool/http2/deadline_test.go').read_bytes()
    archive = subprocess.check_output(['git', 'archive', commit], cwd=root)
    with tempfile.TemporaryDirectory(prefix='tunveo-h2-deadline-') as temp:
        folder = Path(temp)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(folder, filter='data')
        test = template.decode().replace('var expectDeadlineFailure = false', 'var expectDeadlineFailure = ' + ('true' if args.mode == 'original' else 'false'))
        (folder / 'internal/tunnelpool/http2/deadline_test.go').write_text(test)
        run = subprocess.run([args.go, 'test', '-race', '-run', '^TestH2(Read|Write)DeadlineIsolation$',
                              '-count', str(args.repeat), '-v', './internal/tunnelpool/http2'], cwd=folder,
                             env=dict(os.environ, GOTOOLCHAIN='local'), capture_output=True, text=True, timeout=120)
    marker = 'REPRODUCED-' if args.mode == 'original' else 'PASSED-'
    counts = {name.lower(): run.stdout.count(marker + name + ':') for name in ['READ', 'WRITE']}
    result = {'source_commit': commit, 'mode': args.mode, 'scope': 'real TLS HTTP/2 pools, two streams sharing one physical connection; read/write expiry on both endpoints; no source instrumentation',
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'template_sha256': hashlib.sha256(template).hexdigest(), 'repeat_per_scenario': args.repeat,
              'scenarios': counts, 'test_exit_code': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}
    result['status'] = ('reproduced' if args.mode == 'original' else 'passed') if run.returncode == 0 and all(n == args.repeat * 2 for n in counts.values()) else 'failed'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ['source_commit', 'mode', 'status', 'scenarios']}))
    if result['status'] == 'failed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
