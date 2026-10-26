#!/usr/bin/env python3
"""Validate a continuous native soak; short pilots can never qualify as 24 hours."""
import argparse
from collections import Counter
import datetime
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import statistics
import subprocess
import time

MIB = 1024 * 1024
ACTIVE = {'goroutines': 32, 'fd': 16, 'heap_alloc': 32 * MIB, 'rss': 64 * MIB}
TREND = {'goroutines': 4, 'fd': 2, 'heap_alloc': 8 * MIB, 'rss': 32 * MIB}
RETURN = {'goroutines': 4, 'fd': 2, 'heap_alloc': 8 * MIB}


def need(condition, message):
    if not condition:
        raise ValueError(message)



def validate_build(info):
    need('-race=true' not in info, 'formal soak requires an ordinary build; race pilots remain separate')
    need('build\tvcs.modified=false' in info and re.search(r'(?m)^build\tvcs.revision=[0-9a-f]{40}$', info),
         'formal source checkout must be identifiable and unmodified')

def validate_report(r, pilot):
    need(r['schema_version'] == 1 and r['status'] == 'passed' and not r.get('error'), 'probe did not pass')
    s = r['settings']
    need(r['transport'] in range(4) and r['mode'] in (1, 2), 'invalid profile')
    need(s['tls'] == 1 and s['application_attempts'] == 1, 'unsupported traffic policy')
    need(s['tcp_ratio'] == .75 and s['udp_ratio'] == .25, 'unexpected protocol ratio')
    need(s['observed_verifications'] == 2 and s['observed_restarts'] == 0, 'endpoint was not continuously established')
    need(math.isfinite(r['measured_seconds']) and r['measured_seconds'] >= s['duration_seconds'], 'incomplete measured duration')
    need(0 <= r['stop_seconds'] < 5, 'stop deadline')
    for counts in (r['counts'], r['warmup_counts']):
        need(counts['failed'] == 0 and counts['dropped'] == 0, 'traffic failure or offered-load drop')
    count = r['counts']['tcp'] + r['counts']['udp']
    need(count >= .9 * s['duration_seconds'] * s['qps'], 'offered workload was not maintained')
    need(sum(r['warmup_counts'][k] for k in ('tcp', 'udp')) >= .9*s['warmup_seconds']*s['qps'], 'warmup load was not maintained')
    need(r['counts']['tcp'] > 0 and r['counts']['udp'] > 0, 'missing protocol')
    need(abs(r['counts']['tcp'] / count - .75) <= .03, 'traffic mix outside tolerance')
    points = r['points']
    need(len(points) >= 4, 'insufficient resource samples')
    for a, b in zip(points, points[1:]):
        need(0 < b['at_seconds'] - a['at_seconds'] <= 2 * s['sample_interval_seconds'] + 5, 'resource sample gap')
        need(all(b['counts'][k] >= a['counts'][k] for k in ('tcp', 'udp', 'failed', 'dropped')), 'counters went backwards')
    steady = [x for x in points if x['phase'] == 'measured']
    need(len(steady) >= 3, 'insufficient measured resource samples')
    need(steady[0]['at_seconds'] <= s['warmup_seconds'] + 2*s['sample_interval_seconds'] + 5, 'missing beginning of resource window')
    need(steady[-1]['at_seconds'] >= s['warmup_seconds'] + s['duration_seconds'] - 2*s['sample_interval_seconds'] - 5, 'missing end of resource window')
    warm = [x for x in points if x['phase'] == 'warmup' and x['at_seconds'] >= s['warmup_seconds']/2]
    need(len(warm) >= 3, 'loaded warmup envelope requires at least three later warmup samples')
    baseline = {key: max(x['resources'][key] for x in warm) for key in ACTIVE}
    for p in steady:
        for key, allowance in ACTIVE.items():
            need(0 < p['resources'][key] <= baseline[key] + allowance, 'active resource bound: ' + key)
    for key, allowance in RETURN.items():
        need(0 < r['after_stop'][key] <= r['idle_baseline'][key] + allowance, 'resource did not return: ' + key)
    quarter = max(1, len(steady) // 4)
    trend = {key: statistics.median(p['resources'][key] for p in steady[-quarter:]) -
             statistics.median(p['resources'][key] for p in steady[:quarter]) for key in TREND}
    if not pilot:
        need(s['duration_seconds'] >= 86400 and r['measured_seconds'] >= 86400, '24 continuous measured hours required')
        need(s['warmup_seconds'] >= 60 and len(steady) >= 120, 'insufficient long-run warmup/samples')
        validate_build(r['build_info'])
        for key, allowance in TREND.items():
            need(trend[key] <= allowance, 'unexplained long-run resource trend: ' + key)
    return {'exchanges': count, 'measured_seconds': r['measured_seconds'], 'resource_trend': trend,
            'qualifies_24h': not pilot, 'status': 'pilot_passed' if pilot else 'candidate_passed'}


def validate_events(path, r):
    s = r['settings']
    workers = s['workers']
    expected = list(range(workers))
    totals = {'warmup': Counter(), 'measured': Counter()}
    last_hash = [None] * workers
    with gzip.open(path, 'rt') as stream:
        for line in stream:
            e = json.loads(line)
            w = e['worker']
            need(0 <= w < workers and e['sequence'] == expected[w], 'missing, duplicated or reordered worker event')
            expected[w] += workers
            need(abs(e['scheduled_seconds'] - (e['sequence'] + 1) / s['qps']) <= 1 / s['qps'] + .001, 'offered-load tick gap or catch-up burst')
            need(e['phase'] in totals, 'unknown event phase')
            need((e['phase'] == 'measured') == (e['scheduled_seconds'] >= s['warmup_seconds']), 'phase time mismatch')
            need(e['scheduled_seconds'] < s['warmup_seconds'] + s['duration_seconds'], 'event scheduled beyond load window')
            proto = 'udp' if (e['sequence'] // workers + w) % 4 == 3 else 'tcp'
            need(e['protocol'] == proto, 'offered protocol pattern changed')
            size = 512 if proto == 'udp' else 32768
            need(not e.get('error') and e['attempts'] == 1, 'failed or retried application exchange')
            need(e['bytes'] == e['sent_bytes'] == e['received_bytes'] == size, 'payload length mismatch')
            need(e['local'] != e['peer'] and e['peer'] == f"127.0.0.1:{s['front_port']}", 'incorrect or self-connected tuple')
            need(0 < e['duration_seconds'] < 3.1, 'I/O deadline or invalid duration')
            need(re.fullmatch('[0-9a-f]{64}', e['payload_sha256']) is not None and e['payload_sha256'] == e['reply_sha256'], 'payload digest mismatch')
            need(e['payload_sha256'] != last_hash[w], 'repeated payload may conceal stale echo')
            last_hash[w] = e['payload_sha256']
            totals[e['phase']][proto] += 1
    for phase, counts in (('warmup', r['warmup_counts']), ('measured', r['counts'])):
        need(all(totals[phase][key] == counts[key] for key in ('tcp', 'udp')), 'event/report count mismatch')
    return sum(sum(c.values()) for c in totals.values())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--transport', type=int, choices=range(4), required=True)
    p.add_argument('--mode', type=int, choices=(1, 2), required=True)
    p.add_argument('--duration-seconds', type=float)
    p.add_argument('--warmup-seconds', type=float)
    p.add_argument('--sample-seconds', type=float)
    p.add_argument('--pool-min', type=int, default=16)
    p.add_argument('--pool-max', type=int, default=64)
    p.add_argument('--workers', type=int, default=2)
    p.add_argument('--qps', type=int, default=10)
    p.add_argument('--goroutine-diagnostics', action='store_true', help='bounded local stack capture; diagnostic run, not canonical acceptance')
    p.add_argument('--pilot', action='store_true', help='short run, categorically ineligible for the 24h gate')
    p.add_argument('--artifacts', type=Path, required=True)
    a = p.parse_args()
    if a.goroutine_diagnostics and not a.pilot:
        p.error('goroutine diagnostics require --pilot; formal acceptance remains uninstrumented')
    duration = a.duration_seconds if a.duration_seconds is not None else (60 if a.pilot else 86400)
    warmup = a.warmup_seconds if a.warmup_seconds is not None else (12 if a.pilot else 60)
    interval = a.sample_seconds if a.sample_seconds is not None else (5 if a.pilot else 30)
    if any(not math.isfinite(x) or x < 1 for x in (duration, warmup, interval)) or duration > 72 * 3600 or interval > 60:
        p.error('positive finite bounded durations required')
    if warmup < 6 * min(interval, 2):
        p.error('warmup requires at least three later-phase samples; increase warmup or sample more often')
    if not a.pilot and (duration < 86400 or warmup < 60):
        p.error('formal execution requires 24 measured hours and at least 60s warmup; short runs require --pilot')
    if not 1 <= a.workers <= 2 or not 1 <= a.qps <= 50 or not 1 <= a.pool_min <= a.pool_max <= 4096:
        p.error('invalid workload/pool bounds')
    a.artifacts.mkdir(parents=True, exist_ok=False)
    binary = a.binary.resolve(strict=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('NP_', 'TUNVEO_'))}
    summary = {'status': 'running', 'qualifies_24h': False, 'pilot': a.pilot,
               'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
               'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'platform': platform.platform(), 'machine': platform.machine()}
    if not a.pilot:
        try:
            meta = subprocess.run([str(binary), '--describe'], env=env, capture_output=True, text=True, timeout=10, check=True)
            description = json.loads(meta.stdout)
            need(description['goos'] == 'linux', 'formal resource probe requires Linux')
            validate_build(description['build_info'])
            summary['preflight'] = description
        except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
            summary.update(status='failed', qualifies_24h=False, error='preflight: ' + str(exc))
            (a.artifacts / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
            print(json.dumps(summary))
            return 1
    start = time.monotonic()
    command = [str(binary), '--transport', str(a.transport), '--mode', str(a.mode), '--duration', f'{duration}s',
               '--warmup', f'{warmup}s', '--sample-interval', f'{interval}s', '--workers', str(a.workers),
               '--qps', str(a.qps), '--pool-min', str(a.pool_min), '--pool-max', str(a.pool_max), '--artifacts', str(a.artifacts / 'native')]
    if a.goroutine_diagnostics:
        command.append('--goroutine-diagnostics')
        summary['goroutine_diagnostics'] = True
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    previous_term = signal.signal(signal.SIGTERM, interrupted)
    proc = None
    try:
        with (a.artifacts / 'stdout.log').open('w') as stdout, (a.artifacts / 'stderr.log').open('w') as stderr:
            try:
                proc = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
                summary['native_pid'] = proc.pid
                (a.artifacts / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
                summary['exit_code'] = proc.wait(timeout=duration + warmup + 120)
                summary['cleanup'] = {'reaped': True, 'forced_kill': False}
            except (subprocess.TimeoutExpired, KeyboardInterrupt, OSError) as exc:
                summary.update(status='failed', qualifies_24h=False, error=type(exc).__name__, termination_reason=type(exc).__name__)
                forced = False
                if proc is not None:
                    if proc.poll() is None:
                        try:
                            proc.terminate()
                        except ProcessLookupError:
                            pass
                    try:
                        proc.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        forced = True
                        proc.kill()
                        proc.wait(timeout=5)
                    summary['exit_code'] = proc.returncode
                else:
                    summary['exit_code'] = 130
                summary['cleanup'] = {'reaped': True, 'forced_kill': forced, 'interrupted_or_timeout': True}
    finally:
        signal.signal(signal.SIGTERM, previous_term)
    try:
        need(summary['exit_code'] == 0 and summary['status'] != 'failed', 'nonzero, interrupted or timed-out probe')
        native = a.artifacts / 'native'
        r = json.loads((native / 'report.json').read_text())
        need((r['transport'], r['mode']) == (a.transport, a.mode), 'profile mismatch')
        if not a.pilot:
            need(r['build_info'] == summary['preflight']['build_info'], 'build metadata changed after preflight')
        need(r['settings']['duration_seconds'] == duration and r['settings']['warmup_seconds'] == warmup and r['settings']['sample_interval_seconds'] == interval, 'duration settings mismatch')
        need(all(r['settings'][key] == value for key, value in [('qps', a.qps), ('workers', a.workers), ('pool_min', a.pool_min), ('pool_max', a.pool_max)]), 'requested workload mismatch')
        summary.update(validate_report(r, a.pilot))
        summary['audited_events'] = validate_events(native / 'exchanges.jsonl.gz', r)
        with gzip.open(native / 'engine.log.gz', 'rt') as stream:
            verified = 0
            negotiated = []
            for line in stream:
                need(not any(x in line for x in ('DATA RACE', 'panic:', 'fatal error:', 'Client restart', 'Server restart')), 'engine failure/restart')
                verified += 'RAM cert verified with sha256 fingerprint' in line
                if 'Sending tunnel config:' in line or 'Loading tunnel config:' in line:
                    match = re.search(r'MAX=(\d+)\|TLS=(\d+)\|TYPE=(\d+)\|', line)
                    need(match is not None, 'missing negotiated configuration')
                    negotiated.append(tuple(int(x) for x in match.groups()))
        need(verified == 2, 'missing or repeated engine verification')
        need(negotiated == [(a.pool_max, 1, a.transport)] * 2, 'negotiated pool/TLS/transport mismatch')
        need(not any(x in (a.artifacts / 'stderr.log').read_text() for x in ('DATA RACE', 'panic:', 'fatal error:')), 'runtime failure')
    except (ValueError, KeyError, TypeError, OSError, EOFError, json.JSONDecodeError) as exc:
        summary.update(status='failed', qualifies_24h=False, error=f'{type(exc).__name__}: {exc}')
    summary['elapsed_seconds'] = round(time.monotonic() - start, 3)
    summary['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    summary['files'] = {str(path.relative_to(a.artifacts)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in sorted(a.artifacts.rglob('*')) if path.is_file() and path.name != 'summary.json'}
    (a.artifacts / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))
    return 0 if summary['status'] in ('pilot_passed', 'candidate_passed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
