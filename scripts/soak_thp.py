#!/usr/bin/env python3
"""Pilot-only, sequential same-binary THP intervention. Never changes host policy."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import audit_soak_retention as retention
import soak_mappings as mappings

ROOT = Path(__file__).resolve().parent
RUNTIME_KEYS = ('GODEBUG', 'GOGC', 'GOMEMLIMIT', 'GOMAXPROCS')


def dump(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')


def runtime_environment(policy, inherited):
    # Only GODEBUG changes between arms; inherited GC/CPU limits remain identical.
    env = dict(inherited)
    env.pop('GODEBUG', None)
    if policy == 'disablethp':
        env['GODEBUG'] = 'disablethp=1'
    elif policy != 'default':
        raise ValueError('unknown policy')
    return env


def host_snapshot():
    paths = [Path('/proc/self/cgroup'), Path('/proc/self/status'),
             Path('/sys/fs/cgroup/cpu.max'), Path('/sys/fs/cgroup/memory.max')]
    base = Path('/sys/kernel/mm/transparent_hugepage')
    paths += sorted(p for p in base.rglob('*') if p.is_file()) if base.exists() else [base]
    files = {}
    for path in paths:
        try:
            files[str(path)] = {'raw': path.read_text()}
        except OSError as error:
            files[str(path)] = {'error': type(error).__name__+': '+str(error)}
    return {'at_unix_ns': time.time_ns(), 'uname': list(platform.uname()),
            'page_size': os.sysconf('SC_PAGE_SIZE'), 'files': files}


def heap_pages(raw, race):
    # Reuse the strict complete-VMA parser; retain extra raw fields independently.
    parsed = mappings.parse_smaps(raw, race)['mappings']
    extra = []
    current = None
    for line in raw.splitlines():
        if mappings.HEADER.fullmatch(line):
            current = {}; extra.append(current)
        elif current is not None:
            key, _, value = line.partition(':')
            if key in ('AnonHugePages', 'THPeligible', 'VmFlags'):
                if key in current:
                    raise ValueError('duplicate THP field')
                fields = value.split()
                if key == 'AnonHugePages':
                    if len(fields) != 2 or fields[1] != 'kB' or not fields[0].isascii() or not fields[0].isdecimal():
                        raise ValueError('invalid AnonHugePages')
                    current[key] = int(fields[0])*1024
                elif key == 'THPeligible':
                    if fields not in (['0'], ['1']):
                        raise ValueError('invalid THP eligibility')
                    current[key] = int(fields[0])
                else:
                    current[key] = fields
    heap = []
    for vma, fields in zip(parsed, extra, strict=True):
        if vma['path'] == '[anon: Go: heap]':
            if not {'AnonHugePages', 'THPeligible', 'VmFlags'} <= fields.keys():
                raise ValueError('missing Go heap THP evidence')
            heap.append(dict(start=vma['start'], end=vma['end'], rss=vma['bytes']['Rss'], **fields))
    if not heap:
        raise ValueError('missing decorated Go heap mappings')
    return {'rss': sum(v['rss'] for v in heap),
            'anon_huge_pages': sum(v['AnonHugePages'] for v in heap),
            'all_no_hugepage': all('nh' in v['VmFlags'] for v in heap), 'vmas': heap}


def audit_arm(folder, policy, expected_environment, binary_sha):
    result = retention.audit(folder)  # Revalidates load budgets, hashes, logs, ACK and timings.
    capture = json.loads((folder/'mapping-report.json').read_text())
    if capture['binary_sha256'] != binary_sha:
        raise ValueError('paired binaries differ')
    if capture.get('native_runtime_environment') != expected_environment:
        raise ValueError('native runtime environment differs from declared arm')
    report = json.loads((folder/'pilot/native/report.json').read_text())
    points = {mappings.point_key(p): p for p in report['points']+report['post_stop_observation']}
    rows = []
    for record in capture['samples']:
        path = folder/record['file']
        if hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']:
            raise ValueError('THP mapping hash mismatch')
        pages = heap_pages(gzip.open(path, 'rt').read(), capture['race'])
        if policy == 'disablethp' and (pages['anon_huge_pages'] or not pages['all_no_hugepage']):
            raise ValueError('disablethp intervention not observed on every Go heap VMA')
        # Apply existing selected-point 100ms quality bound to ALL THP samples.
        if not 0 <= record['checkpoint_age_seconds'] <= .1 or (record['read_finished_ns']-record['read_started_ns'])/1e9 > .1:
            raise ValueError('THP sample not timely')
        p = points[mappings.point_key(record)]
        rows.append(dict(phase=p['phase'], at_seconds=p['at_seconds'],
                         statm_rss=p['resources']['rss'], heap_alloc=p['resources']['heap_alloc'],
                         go_heap=pages, mapping_sha256=record['sha256']))
    return {'retention': result, 'series': rows, 'policy': policy,
            'native_runtime_environment': capture['native_runtime_environment'],
            'binary_sha256': binary_sha,
            'scope': 'Go heap THP intervention only; not sanitizer-wide THP control or proof of all RSS ownership'}


def run(a):
    a.artifacts.mkdir(parents=True, exist_ok=False)
    binary = a.binary.resolve(strict=True)
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    description = json.loads(subprocess.check_output([str(binary), '--describe']))
    mappings.supported(description)
    order = ['default', 'disablethp'] if a.order == 'default-first' else ['disablethp', 'default']
    manifest = {'binary_sha256': sha, 'description': description, 'order': order,
                'inherited_runtime_environment': {k: os.environ.get(k) for k in RUNTIME_KEYS},
                'arms': [], 'pilot_only': True, 'host_policy_written': False}
    dump(a.artifacts/'experiment.json', manifest)
    failed = False
    for policy in order:
        arm = {'policy': policy, 'host_before': host_snapshot()}
        env = runtime_environment(policy, os.environ)
        expected = {k: env.get(k) for k in RUNTIME_KEYS}
        arm['expected_runtime_environment'] = expected
        folder = a.artifacts/policy
        cmd = [sys.executable, str(ROOT/'soak_mappings.py'), 'capture', '--binary', str(binary),
               '--duration-seconds', '180', '--post-stop-observe-seconds', '120',
               '--diagnostic-go-scavenge', '--artifacts', str(folder)]
        arm['command'] = cmd
        with (a.artifacts/(policy+'-driver.log')).open('w') as log:
            arm['capture_exit_code'] = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
        arm['host_after'] = host_snapshot()
        failed |= arm['capture_exit_code'] != 0
        try:
            arm['audit'] = audit_arm(folder, policy, expected, sha)
            dump(a.artifacts/(policy+'-audit.json'), arm['audit'])
        except (ValueError, KeyError, OSError) as error:
            arm['audit_error'] = type(error).__name__+': '+str(error)
            failed = True
        manifest['arms'].append(arm)
        dump(a.artifacts/'experiment.json', manifest)
        # Each policy runs exactly once, including when its peer failed.
    manifest['status'] = 'failed' if failed else 'pilot_passed'
    manifest['scope'] = 'two sequential fresh processes on one VM; reversed order runs on another VM; no exact cross-VM subtraction or universal causal claim'
    dump(a.artifacts/'experiment.json', manifest)
    return int(failed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--order', choices=['default-first', 'disablethp-first'], required=True)
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
