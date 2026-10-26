#!/usr/bin/env python3
"""External Linux/amd64 Go1.26.10 mapping diagnostics. Budgets remain in verify_soak."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

LLVM = '51bfeff0e4b0757ff773da6882f4d538996c9b04'
RANGES = {'race_shadow': (0x200000000000, 0x21c000000000),
          'race_metadata': (0x300000000000, 0x400000000000)}
FIELDS = ('Size', 'Rss', 'Pss', 'Anonymous', 'Private_Dirty', 'Swap')
HEADER = re.compile(r'^([0-9a-f]+)-([0-9a-f]+) ([rwxps-]{4}) [0-9a-f]+ [0-9a-f]+:[0-9a-f]+ [0-9]+\s*(.*)$')


def classify(start, end, path, race):
    if race:
        for name, (lo, hi) in RANGES.items():
            if start < hi and end > lo:
                return name if lo <= start < end <= hi else 'boundary_crossing'
    if not path or path.startswith('[anon:'):
        return 'other_anonymous'
    return 'kernel_named' if path.startswith('[') else 'file_mapping'


def parse_smaps(raw, race):
    maps = []
    current = None
    for line in raw.splitlines():
        h = HEADER.fullmatch(line)
        if h:
            if current is not None:
                if not set(FIELDS) <= current['bytes'].keys():
                    raise ValueError('incomplete VMA')
                maps.append(current)
            start, end = (int(h[i], 16) for i in (1, 2))
            if start >= end or (current and start < current['end']):
                raise ValueError('overlapping or unordered VMA')
            current = dict(start=start, end=end, permissions=h[3], path=h[4], bytes={})
            current['category'] = classify(start, end, h[4], race)
        else:
            f = line.split()
            if f and f[0].rstrip(':') in FIELDS:
                if current is None or len(f) != 3 or f[2] != 'kB' or not f[1].isascii() or not f[1].isdecimal():
                    raise ValueError('invalid smaps numeric field')
                key = f[0].rstrip(':')
                if key in current['bytes'] or int(f[1]) > (2**64-1)//1024:
                    raise ValueError('duplicate or overflowing field')
                current['bytes'][key] = int(f[1])*1024
            elif line and (current is None or re.match(r'^[0-9a-f]+-', line)):
                raise ValueError('invalid smaps header')
    if current is None or not set(FIELDS) <= current['bytes'].keys():
        raise ValueError('empty or incomplete smaps')
    maps.append(current)
    groups = {}
    for m in maps:
        g = groups.setdefault(m['category'], {k:0 for k in FIELDS})
        for key in FIELDS:
            g[key] += m['bytes'][key]
    return dict(groups=groups, mappings=maps)


def supported(info):
    if (info['go_version'], info['goos'], info['goarch']) != ('go1.26.10', 'linux', 'amd64'):
        raise ValueError('ownership ranges only verified for Go1.26.10 linux/amd64')
    if 'vcs.modified=false' not in info['build_info'] or not re.search(r'vcs.revision=[0-9a-f]{40}', info['build_info']):
        raise ValueError('diagnostics require identifiable clean source')
    return '-race=true' in info['build_info']


def pid_identity(pid):
    return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]


def snapshot(pid, identity, folder, index, race):
    if pid_identity(pid) != identity:
        raise ValueError('PID was reused')
    start = time.time_ns()
    raw = Path(f'/proc/{pid}/smaps').read_text()
    end = time.time_ns()
    if pid_identity(pid) != identity:
        raise ValueError('PID changed during read')
    parsed = parse_smaps(raw, race)
    relative = f'mappings/{index:03d}.smaps.gz'
    path = folder/relative
    path.parent.mkdir(exist_ok=True)
    with gzip.open(path, 'wt') as f:
        f.write(raw)
    return dict(file=relative, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                read_started_ns=start, read_finished_ns=end, groups=parsed['groups'])


def point_key(p):
    return p['phase'], p['at_seconds']


def load_evidence_hash(report):
    keys=("points","counts","warmup_counts","idle_baseline","after_stop","measured_seconds","scheduler_timing","stop_seconds")
    return hashlib.sha256(json.dumps({k:report[k] for k in keys},sort_keys=True,separators=(",",":")).encode()).hexdigest()


def capture(a):
    binary = a.binary.resolve(strict=True)
    info = json.loads(subprocess.check_output([str(binary), '--describe']))
    race = supported(info)
    a.artifacts.mkdir(parents=True, exist_ok=False)
    evidence = dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                    description=info, race=race, llvm_revision=LLVM, samples=[], errors=[])
    cmd = [sys.executable, str(Path(__file__).with_name('verify_soak.py')), '--binary', str(binary),
           '--transport', '3', '--mode', '1', '--pilot', '--duration-seconds', str(a.duration_seconds),
           '--warmup-seconds', '12', '--sample-seconds', '5', '--pool-min', '16',
           '--pool-max', '64', '--workers', '2', '--qps', '10', '--artifacts', str(a.artifacts/'pilot')]
    if a.post_stop_observe_seconds:
        cmd += ['--post-stop-observe-seconds',str(a.post_stop_observe_seconds)]
    if a.diagnostic_go_scavenge:
        cmd.append('--diagnostic-go-scavenge')
        if a.post_stop_observe_seconds:cmd.append('--post-stop-observer-ack')
    seen = set()
    identity = None
    with (a.artifacts/'driver.log').open('w') as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
        try:
            while proc.poll() is None:
                try:
                    summary = json.loads((a.artifacts/'pilot/summary.json').read_text())
                    pid = summary['native_pid']
                    if identity is None:
                        identity = pid_identity(pid)
                        evidence.update(native_pid=pid, native_start_ticks=identity)
                        if hashlib.sha256(Path(f'/proc/{pid}/exe').read_bytes()).hexdigest() != evidence['binary_sha256']:
                            raise ValueError('native executable mismatch')
                    report_path = a.artifacts/'pilot/native/report.json'
                    report = json.loads(report_path.read_text())
                    candidates=[]
                    if report.get('points'):candidates.append(('points',report['points'][-1]))
                    if report.get('post_stop_observation'):candidates.append(('post_stop_observation',report['post_stop_observation'][-1]))
                    for field,p in candidates:
                        key=point_key(p)
                        if key not in seen and p['phase'] in ('warmup','measured','poststop_gc','poststop_go_scavenge'):
                            mtime=report_path.stat().st_mtime_ns
                            snap=snapshot(pid,identity,a.artifacts,len(evidence['samples']),race)
                            newer=json.loads(report_path.read_text())
                            if point_key(newer[field][-1])!=key:raise ValueError('checkpoint changed during mapping read')
                            snap.update(phase=p['phase'],at_seconds=p['at_seconds'],checkpoint_age_seconds=(snap['read_started_ns']-mtime)/1e9,point_statm_rss=p['resources']['rss'])
                            if field=='post_stop_observation':snap['load_evidence_sha256']=load_evidence_hash(report)
                            evidence['samples'].append(snap);seen.add(key)
                            if field=='post_stop_observation' and p['phase']=='poststop_gc' and report['settings'].get('post_stop_observer_ack') and p['at_seconds']>=report['settings']['post_stop_observe_seconds']:
                                if not 0<=snap['checkpoint_age_seconds']<=.1 or (snap['read_finished_ns']-snap['read_started_ns'])/1e9>.1:raise ValueError('pre-scavenge mapping not timely; no acknowledgment')
                                ack=report_path.parent/'post-stop-observer-ack.json'
                                temp=ack.with_suffix('.tmp')
                                temp.write_text(json.dumps({'phase':p['phase'],'at_seconds':p['at_seconds'],'mapping_sha256':snap['sha256'],'load_evidence_sha256':snap['load_evidence_sha256']}))
                                temp.replace(ack)
                except (FileNotFoundError, ProcessLookupError, json.JSONDecodeError, KeyError):
                    pass  # startup/final exit races; audit requires every load checkpoint
                except (ValueError, PermissionError) as e:
                    evidence['errors'].append(str(e))
                    break
                time.sleep(.01)
            code = proc.wait(timeout=a.duration_seconds+a.post_stop_observe_seconds+150)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=35)
    evidence['driver_exit_code'] = code
    (a.artifacts/'mapping-report.json').write_text(json.dumps(evidence, indent=2)+'\n')
    try:
        result = audit(a.artifacts)
        (a.artifacts/'mapping-audit.json').write_text(json.dumps(result, indent=2)+'\n')
    except (ValueError, KeyError, OSError) as e:
        print(f'mapping audit failed: {e}', file=sys.stderr)
        return 1
    return code


def audit(folder):
    import verify_soak as v
    import audit_soak_os_memory as rollup
    e = json.loads((folder/'mapping-report.json').read_text())
    if e['errors'] or e['llvm_revision'] != LLVM or supported(e['description']) != e['race']:
        raise ValueError('mapping capture errors')
    d = folder/'pilot'
    r = json.loads((d/'native/report.json').read_text())
    s = json.loads((d/'summary.json').read_text())
    for f, sha in s['files'].items():
        if hashlib.sha256((d/f).read_bytes()).hexdigest() != sha:
            raise ValueError('pilot hash mismatch')
    if s['exit_code'] != 0 or not s['cleanup']['reaped'] or s['cleanup']['forced_kill'] or s['qualifies_24h'] or not s['pilot']:
        raise ValueError('incomplete pilot')
    if s['binary_sha256'] != e['binary_sha256'] or r['build_info'] != e['description']['build_info']:
        raise ValueError('build mismatch')
    if e['driver_exit_code'] != (0 if s['status'] == 'pilot_passed' else 1):
        raise ValueError('driver exit mismatch')
    expected_error = None
    try:
        v.validate_report(r, True)
    except ValueError as error:
        expected_error = 'ValueError: '+str(error)
    if (s['status'] == 'pilot_passed') != (expected_error is None) or s.get('error') != expected_error:
        raise ValueError('pilot result mismatch')
    events = v.validate_events(d/'native/exchanges.jsonl.gz', r)
    v.validate_engine_logs(d/'native', d/'stderr.log', 64, 3)
    samples = {}
    for point in e['samples']:
        path = folder/point['file']
        if hashlib.sha256(path.read_bytes()).hexdigest() != point['sha256']:
            raise ValueError('mapping hash mismatch')
        parsed = parse_smaps(gzip.open(path, 'rt').read(), e['race'])
        if parsed['groups'] != point['groups'] or 'boundary_crossing' in parsed['groups']:
            raise ValueError('mapping classification mismatch or ambiguous boundary')
        if point_key(point) in samples:
            raise ValueError('duplicate mapping sample')
        samples[point_key(point)] = point
    load = [p for p in r['points'] if p['phase'] in ('warmup', 'measured')]
    expected=load+r.get('post_stop_observation',[])
    if set(map(point_key,expected)) != samples.keys():
        raise ValueError('missing or extra load checkpoint mappings')
    warm = [p for p in load if p['phase'] == 'warmup' and p['at_seconds'] >= 6]
    base = max(warm, key=lambda p:p['resources']['rss'])
    peak = max((p for p in load if p['phase'] == 'measured'), key=lambda p:p['resources']['rss'])
    b, p = samples[point_key(base)], samples[point_key(peak)]
    for point in (b, p):
        if not 0 <= point['checkpoint_age_seconds'] <= .1 or (point['read_finished_ns']-point['read_started_ns'])/1e9 > .1:
            raise ValueError('selected mapping snapshot too far from checkpoint')
    categories = b['groups'].keys() | p['groups'].keys()
    delta = {key:{f:p['groups'].get(key, {}).get(f, 0)-b['groups'].get(key, {}).get(f, 0)
                  for f in FIELDS} for key in sorted(categories)}
    return dict(status=s['status'], error=expected_error, audited_events=events,
                baseline_at_seconds=base['at_seconds'], peak_at_seconds=peak['at_seconds'],
                groups_delta_bytes=delta, smaps_rss_delta=sum(g['Rss'] for g in delta.values()),
                statm_rss_delta=peak['resources']['rss']-base['resources']['rss'],
                selected_checkpoint_age_seconds=[b['checkpoint_age_seconds'],p['checkpoint_age_seconds']],
                max_read_seconds=max((p['read_finished_ns']-p['read_started_ns'])/1e9 for p in samples.values()),
                samples=len(samples), rollup_audit=rollup.audit(d/'native/report.json'),
                scope='post-checkpoint asynchronous smaps; different reads, not atomic attribution')


def control(a):
    a.artifacts.mkdir(parents=True, exist_ok=False)
    rows=[]
    with (a.artifacts/'stderr.log').open('w') as stderr:
        p=subprocess.Popen([str(a.binary.resolve())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,text=True)
        try:
            for i in range(2):
                info=json.loads(p.stdout.readline())
                race=supported(info)
                s=snapshot(p.pid,pid_identity(p.pid),a.artifacts,i,race)
                rows.append(dict(stage=info,snapshot=s))
                p.stdin.write('\n');p.stdin.flush()
            code=p.wait(timeout=10)
        finally:
            if p.poll() is None:p.kill();p.wait()
    delta=rows[1]['snapshot']['groups'].get('race_shadow',{}).get('Rss',0)-rows[0]['snapshot']['groups'].get('race_shadow',{}).get('Rss',0)
    result=dict(exit_code=code,race=race,rows=rows,native_pid=p.pid,shadow_rss_delta=delta,
                expected_shadow_address=rows[1]['stage']['address']*2+RANGES['race_shadow'][0])
    (a.artifacts/'control.json').write_text(json.dumps(result,indent=2)+'\n')
    touched=parse_smaps(gzip.open(a.artifacts/rows[1]['snapshot']['file'], 'rt').read(), race)
    predicted=result['expected_shadow_address']
    result['predicted_shadow_mapping_observed']=any(m['start'] <= predicted < m['end'] and m['category']=='race_shadow' and m['bytes']['Rss'] > 0 for m in touched['mappings'])
    (a.artifacts/'control.json').write_text(json.dumps(result,indent=2)+'\n')
    if code or (race and (delta < 48*1024*1024 or not result['predicted_shadow_mapping_observed'])) or (not race and delta != 0):
        raise ValueError('32MiB touched Go allocation did not produce expected shadow control')
    return 0


def main():
    p=argparse.ArgumentParser(description=__doc__)
    subs=p.add_subparsers(dest='command',required=True)
    for name in ('capture','control'):
        s=subs.add_parser(name);s.add_argument('--binary',type=Path,required=True);s.add_argument('--artifacts',type=Path,required=True)
        if name=='capture':
            s.add_argument('--duration-seconds',type=int,default=60,choices=range(1,3601))
            s.add_argument('--post-stop-observe-seconds',type=int,default=0,choices=[0]+list(range(5,601)))
            s.add_argument('--diagnostic-go-scavenge',action='store_true')
    s=subs.add_parser('audit');s.add_argument('artifacts',type=Path)
    a=p.parse_args()
    if a.command=='audit':
        print(json.dumps(audit(a.artifacts),indent=2));return 0
    return capture(a) if a.command=='capture' else control(a)


if __name__=='__main__':
    raise SystemExit(main())
