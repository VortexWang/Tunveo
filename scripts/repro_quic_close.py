#!/usr/bin/env python3
"""Check immediate UDP rebind after real QUIC pool Close on an immutable archive."""
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
    if a.repeat < 1:
        p.error('repeat must be positive')
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(['git', 'rev-parse', a.ref], cwd=root, text=True).strip()
    archive = subprocess.check_output(['git', 'archive', commit], cwd=root)
    template = (root / 'internal/tunnelpool/quic/close_udp_test.go').read_bytes()
    with tempfile.TemporaryDirectory(prefix='tunveo-quic-close-') as temp:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(temp, filter='data')
        (Path(temp) / 'internal/tunnelpool/quic/close_udp_test.go').write_bytes(template)
        run = subprocess.run([a.go, 'test', '-race', '-count=' + str(a.repeat), '-run',
                              '^TestCloseReleasesUDPAddressWithAcceptedConnection$', '-v', './internal/tunnelpool/quic'],
                             cwd=temp, capture_output=True, text=True, timeout=120)
    failures = run.stdout.count('Close returned before UDP port release:')
    passes = run.stdout.count('--- PASS: TestCloseReleasesUDPAddressWithAcceptedConnection')
    ok = (run.returncode == 0 and passes == a.repeat) if a.mode == 'fixed' else (run.returncode != 0 and failures == a.repeat and passes == 0)
    result = {'status': ('passed' if a.mode == 'fixed' else 'reproduced') if ok else 'failed',
              'source_commit': commit, 'source_archive_sha256': hashlib.sha256(archive).hexdigest(),
              'template_sha256': hashlib.sha256(template).hexdigest(), 'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'production_source_modified': False, 'mode': a.mode, 'repeat': a.repeat,
              'observed_rebind_failures': failures, 'observed_passes': passes,
              'exit_code': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('status', 'source_commit', 'observed_rebind_failures', 'observed_passes')}))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
