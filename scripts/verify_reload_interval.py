#!/usr/bin/env python3
"""Process regression for NP_RELOAD_INTERVAL startup validation (loopback only)."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from verify_security import free_port, request, stop, wait_ready


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    results = []
    report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'helper_sha256': hashlib.sha256(Path(__file__).with_name('verify_security.py').read_bytes()).hexdigest(),
              'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'scope': 'local loopback, temporary master state, synthetic credentials', 'results': results}
    try:
        with tempfile.TemporaryDirectory(prefix='tunveo-reload-') as temp:
            folder = Path(temp)
            local = folder / 'tunveo'
            shutil.copy2(binary, local)
            for role in ('master', 'server', 'client'):
                for label, value in [('zero', '0'), ('zero-unit', '0s'), ('negative', '-1s'),
                                     ('empty', ''), ('malformed', 'fixture-invalid-secret'),
                                     ('overflow', '9223372036854775808ns')]:
                    port = free_port()
                    env = dict(os.environ, NP_RELOAD_INTERVAL=value)
                    url = f'{role}://fixture-url-secret@127.0.0.1:{port}/127.0.0.1:1?log=debug'
                    r = subprocess.run([str(local), url], env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, timeout=5)
                    ok = (r.returncode == 1 and 'NP_RELOAD_INTERVAL' in r.stdout
                          and 'strictly positive' in r.stdout and 'panic:' not in r.stdout
                          and 'fixture-url-secret' not in r.stdout
                          and 'fixture-invalid-secret' not in r.stdout)
                    with socket.socket() as sock:
                        sock.settimeout(.2)
                        listening = sock.connect_ex(('127.0.0.1', port)) == 0
                    state_created = (folder / 'gob').exists()
                    results.append({'case': f'{role}/{label}', 'status': 'passed' if ok and not listening and not state_created else 'failed',
                                    'exit_code': r.returncode, 'panic': 'panic:' in r.stdout,
                                    'listening_after_exit': listening, 'state_created': state_created})
                    assert ok and not listening and not state_created, 'invalid interval did not fail cleanly before startup'
            # The default and positive settings still start, authenticate and stop.
            # The short positive setting must actually execute a maintenance tick.
            current_key = None
            for label, value in [('unset-default', None), ('positive-short', '50ms'), ('positive-hour', '1h')]:
                env = dict(os.environ)
                env.pop('NP_RELOAD_INTERVAL', None)
                if value is not None:
                    env['NP_RELOAD_INTERVAL'] = value
                port = free_port()
                proc = subprocess.Popen([str(local), f'master://127.0.0.1:{port}?log=debug'],
                                        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                try:
                    wait_ready(proc, port)
                    state = folder / 'gob/tunveo.gob'
                    read = subprocess.run([str(local), 'api-key', '--state', str(state)],
                                          env=env, capture_output=True, text=True, timeout=3, check=True)
                    current_key = read.stdout.strip()
                    assert len(current_key) == 32
                    assert request(port, 'info', current_key)[0] == 200
                    if label == 'positive-short':
                        deadline = time.monotonic() + 3
                        while not Path(str(state) + '.backup').exists():
                            assert proc.poll() is None and time.monotonic() < deadline
                            time.sleep(.025)
                finally:
                    logs = stop(proc)
                assert 'panic:' not in logs and current_key not in logs
                results.append({'case': f'master/{label}', 'status': 'passed', 'exit_code': 0,
                                'maintenance_backup_observed': label == 'positive-short'})
            # Utility commands do not start a service and remain usable to repair
            # or inspect a deployment whose environment is invalid.
            invalid = dict(os.environ, NP_RELOAD_INTERVAL='0s')
            for command in (['help'], ['version'], ['api-key', '--state', str(state)]):
                r = subprocess.run([str(local), *command], env=invalid, capture_output=True,
                                   text=True, timeout=3)
                assert r.returncode == 0 and not r.stderr
                if command[0] == 'api-key':
                    assert r.stdout.strip() == current_key
                results.append({'case': f'utility/{command[0]}-with-invalid-env', 'status': 'passed', 'exit_code': 0})
        report['status'] = 'passed'
    except Exception as e:
        report['status'] = 'failed'
        report['failure_type'] = type(e).__name__
        raise
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'passed': sum(x['status'] == 'passed' for x in results),
                          'failed': sum(x['status'] == 'failed' for x in results)}))


if __name__ == '__main__':
    main()
