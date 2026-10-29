#!/usr/bin/env python3
"""Same-process mapping ledger through post-stop GC and explicit Go scavenging.

Diagnostic only: original 180s load, after_stop, resource budgets and failures
are frozen. Post-stop observations use a separate clock and evidence file.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

import audit_soak_os_memory as rollup
import audit_soak_retention as retention
import soak_mapping_ledger as ledger
import soak_mappings as mappings
import soak_ret_context as context
import verify_soak as verify

DURATION = 180
POST_STOP = 120
OBSERVER_TIMEOUT = 450


def timely(record, exec_ns=0):
    start, end = record['read_start_monotonic_ns'], record['read_end_monotonic_ns']
    if not (exec_ns <= start <= end and end-start <= 100000000
            and 0 <= record['checkpoint_age_seconds'] <= .1):
        raise ValueError('post-stop mapping timing failure')


def acknowledge(folder, report, records):
    """Only acknowledge a complete, timely prefix, after raw evidence is durable."""
    points = report['post_stop_observation']
    point = points[-1]
    if point['phase'] != 'poststop_gc' or point['at_seconds'] < POST_STOP:
        return
    if [r['key'] for r in records] != [[p['phase'], p['at_seconds']] for p in points]:
        raise ValueError('missing pre-scavenge mapping; acknowledgment blocked')
    record = records[-1]
    timely(record)
    ack = dict(phase=point['phase'], at_seconds=point['at_seconds'],
               mapping_sha256=record['sha256'],
               record_sha256=ledger.point_sha(record),
               load_evidence_sha256=record['load_evidence_sha256'])
    path = folder/'native/post-stop-observer-ack.json'
    temp = path.with_suffix('.tmp')
    context.dump(temp, ack)
    temp.replace(path)


class Collector:
    def __init__(self, folder, binary, *, acknowledger=None):
        self.folder = folder
        self.acknowledger = acknowledge if acknowledger is None else acknowledger
        self.binary = binary.resolve()
        self.active = ledger.Collector(folder, binary)
        self.records = []
        self.seen = set()
        self.load_sha = None

    def __call__(self):
        self.active()
        if self.active.pid is None or not self.active.verified:
            return
        pid, identity = self.active.pid, self.active.start
        report_path = self.folder/'native/report.json'
        try:
            report = json.loads(report_path.read_text())
        except (FileNotFoundError, ProcessLookupError):
            return
        if not report.get('post_stop_observation'):
            return
        point = report['post_stop_observation'][-1]
        key = (point['phase'], point['at_seconds'])
        if key in self.seen:
            return
        if point['phase'] not in ('poststop_gc', 'poststop_go_scavenge'):
            raise ValueError('unexpected post-stop phase')
        load_sha = mappings.load_evidence_hash(report)
        if self.load_sha is not None and self.load_sha != load_sha:
            raise ValueError('original load/after_stop changed during retention')
        self.load_sha = load_sha
        exe, expected = Path(f'/proc/{pid}/exe').stat(), self.binary.stat()
        if mappings.pid_identity(pid) != identity or (exe.st_dev, exe.st_ino) != (expected.st_dev, expected.st_ino):
            raise ValueError('post-stop PID/executable changed')
        mtime = report_path.stat().st_mtime_ns
        wall = time.time_ns()
        start = time.monotonic_ns()
        raw = Path(f'/proc/{pid}/smaps').read_text()
        end = time.monotonic_ns()
        newer = json.loads(report_path.read_text())
        if newer['post_stop_observation'][-1] != point or mappings.pid_identity(pid) != identity:
            raise ValueError('post-stop point/PID changed during smaps read')
        if mappings.load_evidence_hash(newer) != load_sha:
            raise ValueError('load evidence changed during smaps read')
        relative = f'retention-mappings/{len(self.records):03d}.smaps.gz'
        target = self.folder/relative
        target.parent.mkdir(exist_ok=True)
        with gzip.open(target, 'wt') as stream:
            stream.write(raw)
        record = dict(key=list(key), source_field='post_stop_observation', point=point,
            point_sha256=ledger.point_sha(point), file=relative,
            sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
            read_start_monotonic_ns=start, read_end_monotonic_ns=end,
            checkpoint_age_seconds=(wall-mtime)/1e9, pid=pid, start_ticks=identity,
            load_evidence_sha256=load_sha)
        try:
            timely(record)
        except ValueError:
            # Preserve the rejected timing evidence; no ACK or accepted record.
            context.dump(self.folder/'rejected-timing.json', record)
            raise
        self.records.append(record)
        context.dump(self.folder/'retention-snapshots.json', dict(format_version=1,
            clock='CLOCK_MONOTONIC', records=self.records))
        self.seen.add(key)
        self.acknowledger(self.folder, newer, self.records)


def audit_retention(folder, parsed, report):
    settings = report['settings']
    if (settings['duration_seconds'] != DURATION or settings['post_stop_observe_seconds'] != POST_STOP
            or not settings['diagnostic_go_scavenge'] or not settings['post_stop_observer_ack']):
        raise ValueError('unexpected mapping-retention configuration')
    gc, scavenged = retention.validate_retention_points(report)
    capture = json.loads((folder/'retention-snapshots.json').read_text())
    if capture['format_version'] != 1 or capture['clock'] != 'CLOCK_MONOTONIC':
        raise ValueError('invalid retention mapping schema/clock')
    records = capture['records']
    wanted = report['post_stop_observation']
    if [r['key'] for r in records] != [[p['phase'], p['at_seconds']] for p in wanted]:
        raise ValueError('missing/duplicate/reordered retention mappings')
    load_sha = mappings.load_evidence_hash(report)
    execution = json.loads((folder/'execution.json').read_text())
    if not execution['target_identity_verified'] or not execution['group_gone']:
        raise ValueError('retention identity/cleanup missing')
    identity = execution['target_identity']
    calls = ledger.prepare(parsed['calls'])
    family = ledger.prepare([dict(c, owner='observed_race_runtime' if c['contexts'] else 'unresolved')
                             for c in parsed['calls']])
    out = []
    for record, point in zip(records, wanted):
        if (record['source_field'] != 'post_stop_observation' or record['point'] != point
                or record['point_sha256'] != ledger.point_sha(point)
                or record['load_evidence_sha256'] != load_sha):
            raise ValueError('retention point/load evidence changed')
        if (record['pid'] != parsed['native_pid'] or record['pid'] != identity['pid']
                or record['start_ticks'] != str(identity['start_ticks'])):
            raise ValueError('retention process identity mismatch')
        timely(record, parsed['target_exec_ns'])
        path = folder/record['file']
        if hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']:
            raise ValueError('retention mapping hash mismatch')
        os_memory = point['resources']['os_memory']
        if os_memory.get('error') or rollup.parse_rollup(os_memory['smaps_rollup_raw']) != os_memory['bytes']:
            raise ValueError('retention rollup mismatch')
        raw = gzip.open(path, 'rt').read()
        fine = ledger.attribute(raw, True, calls, record['read_start_monotonic_ns'], record['read_end_monotonic_ns'])
        coarse = ledger.attribute(raw, True, family, record['read_start_monotonic_ns'], record['read_end_monotonic_ns'])
        if sum(fine['groups_rss_bytes'].values()) != sum(coarse['groups_rss_bytes'].values()):
            raise ValueError('retention attribution conservation failure')
        out.append(dict(key=record['key'], point=point, fine=fine, family=coarse,
            read_end_monotonic_ns=record['read_end_monotonic_ns']))
    pre_index = len(gc)-1
    pre = records[pre_index]
    ack = json.loads((folder/'native/post-stop-observer-ack.json').read_text())
    expected_ack = dict(phase=gc[-1]['phase'], at_seconds=gc[-1]['at_seconds'],
        mapping_sha256=pre['sha256'], record_sha256=ledger.point_sha(pre), load_evidence_sha256=load_sha)
    if ack != expected_ack:
        raise ValueError('pre-scavenge acknowledgment mismatch')
    if records[pre_index+1]['read_start_monotonic_ns'] <= pre['read_end_monotonic_ns']:
        raise ValueError('post-scavenge mapping not after pre-scavenge mapping')
    return dict(status='retention_audit_passed', load_evidence_sha256=load_sha,
        observer_acknowledgment=ack, snapshots=out, gc_samples=len(gc),
        selected=dict(first_gc=out[0],last_gc=out[pre_index],go_scavenge=out[-1]),
        scope='same-process mapping request origins, repeated forced-GC then explicit Go scavenging; '
            'separate post-stop clock, not natural idle or object/cache/leak proof; original load budget unchanged')


def compare_maps(before, after, calls):
    if after['read_end_monotonic_ns'] <= before['read_end_monotonic_ns']:
        raise ValueError('mapping comparison monotonic order failure')
    a, b = before['family'], after['family']
    signature = lambda v: (v['start'],v['end'],tuple(v['generations']),v['owner'])
    old = {signature(v):v for v in a['unnamed_vmas']}
    new = {signature(v):v for v in b['unnamed_vmas']}
    common = old.keys() & new.keys()
    groups = a['groups_rss_bytes'].keys() | b['groups_rss_bytes'].keys()
    return dict(from_key=before['key'],to_key=after['key'],
        statm_rss_delta=after['point']['resources']['rss']-before['point']['resources']['rss'],
        groups_rss_delta={k:b['groups_rss_bytes'].get(k,0)-a['groups_rss_bytes'].get(k,0) for k in sorted(groups)},
        same_bounds_generations_owner_rss_delta=sum(new[k]['rss']-old[k]['rss'] for k in common),
        changed_or_removed_vmas=[old[k] for k in sorted(old.keys()-new.keys())],
        changed_or_added_vmas=[new[k] for k in sorted(new.keys()-old.keys())],
        memory_syscalls=dict(Counter(c['call'] for c in calls if
            before['read_end_monotonic_ns'] < c['end_ns'] <= after['read_end_monotonic_ns'])),
        scope='whole-VMA endpoint identities; changed bounds are not object allocations/releases; no RSS prorating')


def add_load_comparisons(folder, parsed, report, result):
    peak = max((p for p in report['points'] if p['phase']=='measured'),key=lambda p:p['resources']['rss'])
    capture=json.loads((folder/'snapshots.json').read_text())
    record=next(r for r in capture['records'] if r['key']==[peak['phase'],peak['at_seconds']])
    family=ledger.prepare([dict(c,owner='observed_race_runtime' if c['contexts'] else 'unresolved')
                           for c in parsed['calls']])
    raw=gzip.open(folder/record['file'],'rt').read()
    row=dict(key=record['key'],point=peak,read_end_monotonic_ns=record['read_end_monotonic_ns'],
        family=ledger.attribute(raw,True,family,record['read_start_monotonic_ns'],record['read_end_monotonic_ns']))
    selected=result['selected']
    selected['load_peak']=row
    result['transitions']=[compare_maps(selected[a],selected[b],parsed['calls']) for a,b in
        [('load_peak','first_gc'),('first_gc','last_gc'),('last_gc','go_scavenge')]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('binary', 'control', 'tracer', 'artifacts'):
        parser.add_argument('--'+flag, type=Path, required=True)
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=False)
    result = dict(status='failed', pilot_only=True, qualifies_24h=False, stages=[])
    try:
        if os.sysconf('SC_PAGE_SIZE') != ledger.PAGE:
            raise ValueError('only 4096-byte Linux pages supported')
        folder = args.artifacts/'control'
        parsed = context.launch(args.control, folder, ledger.CONTROL, [str(folder.resolve())],45,
            args.tracer, program_builder=ledger.program, auditor=ledger.parse,
            poll_hook=ledger.Collector(folder,args.control,True))
        result['control'] = dict(ledger=parsed,snapshots=ledger.audit_snapshots(folder,parsed,False,True))
        result['stages'].append('control_passed')
        binary = args.binary.resolve()
        info = json.loads(subprocess.check_output([str(binary),'--describe']))
        if not mappings.supported(info):
            raise ValueError('mapping-retention requires supported race build')
        folder = args.artifacts/'pilot'
        native = (folder/'native').resolve()
        parsed = context.launch(binary,folder,context.SYMBOLS,
            ['--transport','3','--mode','1','--duration','180s','--warmup','12s',
             '--sample-interval','5s','--workers','2','--qps','10','--pool-min','16','--pool-max','64',
             '--post-stop-observe','120s','--diagnostic-go-scavenge','--post-stop-observer-ack',
             '--artifacts',str(native)],OBSERVER_TIMEOUT,args.tracer,
            program_builder=ledger.program,auditor=ledger.parse,poll_hook=Collector(folder,binary))
        report = json.loads((native/'report.json').read_text())
        if report['build_info'] != info['build_info'] or report['settings']['pid'] != parsed['native_pid']:
            raise ValueError('mapping-retention build/PID mismatch')
        result.update(description=info,pilot=dict(ledger=parsed,
            snapshots=ledger.audit_snapshots(folder,parsed,True)))
        result['stages'].append('mapping_audit_passed')
        result['retention'] = audit_retention(folder,parsed,report)
        add_load_comparisons(folder,parsed,report,result['retention'])
        result['stages'].append('retention_audit_passed')
        result['events'] = verify.validate_events(native/'exchanges.jsonl.gz',report)
        verify.validate_engine_logs(native,folder/'native-stderr.log',64,3)
        result['acceptance'] = verify.validate_report(report,True)
        result['status'] = 'diagnostic_passed'
    except (ValueError,KeyError,OSError,AssertionError,subprocess.SubprocessError) as error:
        result['error'] = type(error).__name__+': '+str(error)
    finally:
        context.dump(args.artifacts/'experiment.json',result)
    return int(result['status'] != 'diagnostic_passed')


if __name__ == '__main__':
    raise SystemExit(main())
