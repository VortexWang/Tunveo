#!/usr/bin/env python3
"""Controlled native TCP handler schedule in an isolated git archive.

Only the temporary compiled fixture is instrumented. Original mode pauses after
ID send, before map store. Fixed mode pauses after atomic queue publication.
The real handleConnection and IncomingGet run with loopback TCP sockets.
A second case performs two complete publications without pausing a producer,
then takes the second ID before asking for the first via FIFO.
"""
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
    template = (root / 'scripts/fixtures/publication_schedule_test.go.txt').read_text()
    archive = subprocess.check_output(['git', 'archive', commit], cwd=root)
    with tempfile.TemporaryDirectory(prefix='tunveo-publication-') as temp:
        folder = Path(temp)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(folder, filter='data')
        source = folder / 'internal/tunnelpool/tcp/pool.go'
        original = source.read_bytes()
        text = original.decode().replace('\r\n', '\n')
        if args.mode == 'original':
            needle = '\tcase p.idChan <- id:\n\t\tp.conns.Store(id, conn)'
            replacement = '\tcase p.idChan <- id:\n\t\tpublicationScheduleHook()\n\t\tp.conns.Store(id, conn)'
        else:
            needle = '\tconn = nil\n}\n\nfunc (p *Pool) ClientManager'
            replacement = '\tpublicationScheduleHook()\n\tconn = nil\n}\n\nfunc (p *Pool) ClientManager'
        assert text.count(needle) == 1, 'source anchor changed; review instrumentation'
        text = text.replace(needle, replacement)
        text += '\nvar publicationScheduleHook = func() {}\n'
        source.write_text(text)
        test = template + '\nconst expectPublicationFailure = ' + ('true' if args.mode == 'original' else 'false') + '\n'
        (source.parent / 'publication_schedule_test.go').write_text(test)
        env = dict(os.environ, GOTOOLCHAIN='local')
        run = subprocess.run([args.go, 'test', '-race', '-run', '^Test(PublicationSchedule|MatchingIDNotification)$',
                              '-count', str(args.repeat), '-v', './internal/tunnelpool/tcp'],
                             cwd=folder, env=env, capture_output=True, text=True, timeout=120)
    marker = 'REPRODUCED:' if args.mode == 'original' else 'PASSED:'
    observed = run.stdout.count(marker)
    matching_marker = 'REPRODUCED-MATCH:' if args.mode == 'original' else 'PASSED-MATCH:'
    matching = run.stdout.count(matching_marker)
    result = {'source_commit': commit, 'mode': args.mode, 'source_path': 'internal/tunnelpool/tcp/pool.go',
              'original_source_sha256': hashlib.sha256(original).hexdigest(),
              'instrumented_source_sha256': hashlib.sha256(text.encode()).hexdigest(),
              'test_template_sha256': hashlib.sha256(template.encode()).hexdigest(),
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'scope': 'real TCP handler/getter; test-only scheduling barrier; not a live deployment failure rate',
              'iterations_per_scenario': args.repeat, 'scenarios': {'publication_order': observed, 'matching_id': matching}, 'observed_cases': observed + matching, 'test_exit_code': run.returncode,
              'status': ('reproduced' if args.mode == 'original' else 'passed') if run.returncode == 0 and observed == matching == args.repeat else 'failed',
              'test_output': run.stdout, 'stderr': run.stderr}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ['source_commit', 'mode', 'status', 'observed_cases']}))
    if result['status'] == 'failed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
