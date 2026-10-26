#!/usr/bin/env python3
"""Prove a controlled synchronous checkpoint can make the load harness miss ticks."""
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
    p.add_argument('--go', required=True)
    p.add_argument('--repeat', type=int, default=10)
    p.add_argument('--require-timing', action='store_true')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if not 1 <= a.repeat <= 100:
        p.error('repeat must be1..100')
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(['git', 'rev-parse', a.ref], cwd=root, text=True).strip()
    archive = subprocess.check_output(['git', 'archive', commit], cwd=root)
    template = (root / 'scripts/soak24h/scheduler_control_test.go').read_bytes()
    with tempfile.TemporaryDirectory(prefix='tunveo-checkpoint-control-') as temp:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(temp, filter='data')
        (Path(temp) / 'scripts/soak24h/scheduler_control_test.go').write_bytes(template)
        run = subprocess.run([a.go, 'test', '-race', '-count=' + str(a.repeat), '-run',
                              '^TestCheckpointStallControl$', '-v', './scripts/soak24h'],
                             cwd=temp, capture_output=True, text=True, timeout=180)
    rows = []
    for line in run.stdout.splitlines():
        if 'CHECKPOINT-STALL-CONTROL: ' in line:
            rows.append(json.loads(line.split('CHECKPOINT-STALL-CONTROL: ', 1)[1]))
    valid = run.returncode == 0 and len(rows) == a.repeat and 'DATA RACE' not in run.stdout + run.stderr
    valid = valid and all(r['status'] == 'failed' and r['warmup_counts']['dropped'] >= 1 and
                          r['measured_seconds'] == 0 and 'scheduler missed' in r['error'] for r in rows)
    if a.require_timing:
        valid = valid and all(r.get('scheduler_timing', {}).get('max_checkpoint_seconds', 0) >= .2 and
                              r['scheduler_timing']['missed_slots'] >= 1 for r in rows)
    report = dict(status='passed' if valid else 'failed', source_commit=commit, repeat=a.repeat,
                  template_sha256=hashlib.sha256(template).hexdigest(), archive_sha256=hashlib.sha256(archive).hexdigest(),
                  require_timing=a.require_timing, exit_code=run.returncode, observations=rows,
                  stdout=run.stdout, stderr=run.stderr,
                  scope='injected250ms checkpoint delay in a real loopback echo fixture; proves possible harness coupling, not historical CI attribution; expected probe failures remain failures')
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k not in ('stdout', 'stderr', 'observations')}))
    return 0 if valid else 1


if __name__ == '__main__':
    raise SystemExit(main())
