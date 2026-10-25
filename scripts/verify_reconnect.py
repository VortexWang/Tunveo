#!/usr/bin/env python3
"""Restart one real peer while the other process stays alive, then verify echo."""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from verify_forwarding import CapturedLog, Reservation, clean, echo_service, exchange, stop_processes, atomic_json


def run_case(binary, transport, mode, folder):
    folder.mkdir()
    processes, captures = [], []
    result = {'transport': transport, 'mode': mode, 'status': 'running', 'exchanges': [], 'cleanup': []}
    env = {k: v for k, v in os.environ.items() if not k.startswith(('NP_', 'TUNVEO_'))}
    # Accelerate protocol reporting and retry, without changing application retries.
    env.update(NP_REPORT_INTERVAL='100ms', NP_SERVICE_COOLDOWN='100ms')
    def launch(role, url, suffix):
        capture = CapturedLog(folder / f'{role}-{suffix}.log')
        proc = subprocess.Popen([str(binary), url], cwd=folder, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, errors='replace', bufsize=1)
        capture.start(proc.stdout)
        processes.append(proc)
        captures.append(capture)
        return proc, capture
    def wait_milestones(live, logs, offsets):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            texts = [c.snapshot()[offset:] for c, offset in zip(logs, offsets)]
            if any(p.poll() is not None for p in live):
                raise AssertionError('peer exited during reconnect')
            if any('DATA RACE' in c.snapshot() or 'panic:' in c.snapshot() for c in captures):
                raise AssertionError('engine race/panic')
            if all('RAM cert verified with sha256 fingerprint' in text for text in texts):
                return
            time.sleep(.025)
        raise TimeoutError('reconnect verification deadline')
    try:
        with echo_service() as target:
            front_res, tunnel_res = Reservation(), Reservation()
            front, tunnel = front_res.port, tunnel_res.port
            server_target, client_target = (front, target) if mode == 1 else (target, front)
            server_url = f'server://reconnect-fixture@127.0.0.1:{tunnel}/127.0.0.1:{server_target}?mode={mode}&type={transport}&tls=1&max=8&log=debug'
            client_url = f'client://reconnect-fixture@127.0.0.1:{tunnel}/127.0.0.1:{client_target}?mode=2&min=2&log=debug'
            tunnel_res.close()
            front_res.close()
            server, server_log = launch('server', server_url, 'first')
            client, client_log = launch('client', client_url, 'persistent')
            result['persistent_client_pid'] = client.pid
            wait_milestones([server, client], [server_log, client_log], [0, 0])
            for udp in (False, True):
                result['exchanges'].append({'stage': 'before', 'udp': udp, **exchange(front, udp=udp)})
            stopped = stop_processes([server], 5)
            result['replaced_server_cleanup'] = stopped
            assert all(not x['forced_kill'] and x['returncode'] == 0 for x in stopped)
            server_log.finish()
            # Start reading after the original run's completed verification.
            offset = len(client_log.snapshot())
            replacement, replacement_log = launch('server', server_url, 'replacement')
            wait_milestones([replacement, client], [replacement_log, client_log], [0, offset])
            assert client.pid == result['persistent_client_pid'] and client.poll() is None
            for udp in (False, True):
                result['exchanges'].append({'stage': 'after', 'udp': udp, **exchange(front, udp=udp)})
        result['status'] = 'passed'
    except Exception as e:
        result.update(status='failed', failure_type=type(e).__name__, error=clean(str(e)))
    finally:
        result['cleanup'] = stop_processes(processes, 5)
        for capture in captures:
            capture.finish()
        if any(x['forced_kill'] or x['returncode'] != 0 for x in result['cleanup']):
            result.update(status='failed', cleanup_failed=True)
        if any('DATA RACE' in c.snapshot() or 'panic:' in c.snapshot() for c in captures):
            result.update(status='failed', race_or_panic=True)
        result['logs'] = [str(c.path) for c in captures]
        atomic_json(folder / 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--transport', type=int, action='append')
    parser.add_argument('--mode', type=int, action='append')
    parser.add_argument('--workers', type=int, default=2)
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    report = {'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'scope': 'loopback TLS=1, one server replacement per case; client PID preserved; each echo exchange attempted once',
              'results': []}
    cases = [(t, m) for t in (args.transport or range(4)) for m in (args.mode or (1, 2))]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(run_case, binary, t, m, args.artifacts / f'{t}-{m}') for t, m in cases]
        for future in concurrent.futures.as_completed(futures):
            report['results'].append(future.result())
            atomic_json(args.artifacts / 'report.json', report)
    report['status'] = 'passed' if all(r['status'] == 'passed' for r in report['results']) else 'failed'
    atomic_json(args.artifacts / 'report.json', report)
    print(json.dumps({'status': report['status'], 'passed': sum(r['status'] == 'passed' for r in report['results']), 'total': len(cases)}))
    if report['status'] == 'failed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
