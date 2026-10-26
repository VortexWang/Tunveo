#!/usr/bin/env python3
"""Run and validate the bounded, same-process native endpoint acceptance probe."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

KINDS = {'fresh-pair', 'replace-server'}
LIMITS = {'goroutines': 4, 'fd': 2, 'heap_alloc': 8 * 1024 * 1024}


def validate(report, cycles):
    """Refuse incomplete rows or unsupported evidence instead of counting a green exit."""
    assert report['schema_version'] == 1 and report['status'] == 'passed'
    assert report['requested_cycles_per_scenario'] == cycles
    assert report['transport'] in range(4)
    scenarios = report['scenarios']
    assert len(scenarios) == 4
    assert {(s['kind'], s['mode']) for s in scenarios} == {(k, m) for k in KINDS for m in (1, 2)}
    for s in scenarios:
        assert not s.get('error') and s['warmup'] >= 5
        rows = s['cycles']
        assert len(rows) == cycles and [r['number'] for r in rows] == list(range(1, cycles + 1))
        assert [x['cycle'] for x in s.get('samples', [])] == list(range(10, cycles + 1, 10))
        for row in rows:
            assert not row.get('error') and 0 <= row['stop_seconds'] < 5
            assert 0 < row['duration_seconds'] < 45
            assert len(row['exchanges']) == 2
            assert {x['protocol'] for x in row['exchanges']} == {'tcp', 'udp'}
            for x in row['exchanges']:
                assert x['attempts'] == 1 and x['local'] != x['peer']
                assert x['bytes'] == (32768 if x['protocol'] == 'tcp' else 512)
        for x in [s['baseline'], *s['samples'], s['final']]:
            for metric in ('goroutines', 'fd', 'heap_alloc', 'heap_inuse', 'sys', 'rss'):
                assert x[metric] > 0
        assert s['baseline']['cycle'] == 0 and s['final']['cycle'] == cycles
        for key, allowance in LIMITS.items():
            assert s['final'][key] <= s['baseline'][key] + allowance, (s['kind'], s['mode'], key)
        if s['kind'] == 'fresh-pair':
            for x in s['samples']:
                for key, allowance in LIMITS.items():
                    assert x[key] <= s['baseline'][key] + allowance
    return {'cycles': 4 * cycles, 'exchanges': 8 * cycles, 'resource_scenarios': 4}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--transport', required=True, type=int, choices=range(4))
    parser.add_argument('--cycles', type=int, default=100)
    parser.add_argument('--artifacts', required=True, type=Path)
    args = parser.parse_args()
    if args.cycles < 1:
        parser.error('cycles must be positive')
    args.artifacts.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve(strict=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('NP_', 'TUNVEO_'))}
    env.update(NP_REPORT_INTERVAL='100ms', NP_SERVICE_COOLDOWN='100ms')
    result = {'status': 'running', 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'environment': {'platform': platform.platform(), 'machine': platform.machine()},
              'scope': 'Linux loopback TLS1 min2:max8, both flows; fresh endpoint pairs and persistent client with server replacement; same-process GC heap/FD/goroutine samples. RSS recorded without a return assertion.'}
    start = time.monotonic()
    with (args.artifacts / 'stdout.log').open('w') as stdout, (args.artifacts / 'stderr.log').open('w') as stderr:
        try:
            run = subprocess.run([str(binary), '--transport', str(args.transport), '--cycles', str(args.cycles),
                                  '--warmup', '5', '--artifacts', str(args.artifacts / 'native')],
                                 env=env, stdout=stdout, stderr=stderr, timeout=1200)
            result['exit_code'] = run.returncode
        except subprocess.TimeoutExpired:
            result.update(exit_code=124, error='outer process deadline')
    result['duration_seconds'] = round(time.monotonic() - start, 3)
    try:
        assert result['exit_code'] == 0, 'nonzero probe exit'
        native = json.loads((args.artifacts / 'native/report.json').read_text())
        assert native['transport'] == args.transport
        for path in ('stderr.log', 'native/engine.log'):
            text = (args.artifacts / path).read_text()
            assert 'DATA RACE' not in text and 'panic:' not in text and 'fatal error:' not in text, path
        result.update(validate(native, args.cycles), status='passed')
    except (AssertionError, KeyError, OSError, ValueError, TypeError) as exc:
        result.update(status='failed', error=type(exc).__name__ + ': ' + str(exc))
    result['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (args.artifacts / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
