#!/usr/bin/env python3
"""Offline audit of PR29's immutable failed 180s pilot and TLS failure shard.

Run from the repository root with the original Actions ZIPs. A successful audit
means the preserved failure is reproducible; it never qualifies a soak run.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import importlib
import json
from pathlib import Path
import re
import sys
import tempfile
import zipfile

MIB = 1048576
SOURCE = 'd3650a1c2cbb214968e26f16424c2a5e0104b7a9'
CHECKOUT = '697040f541d60df39c9ecc87d5eef0ae53fd9859'
TREE = '3796b71a5a19b2e4df60f88b2347d27fbbcfd50b'
TRACER = '93c593f6dab2e930d6198cfaa52b29d19a8c0647'
SOURCES = {
    'audit_soak_os_memory.py': '0c5fbff721f98f94fb75f431da968679908d1171',
    'soak_mapping_ledger.py': '23c39d668502b4f3865a6e9347b0bed811f0a1c9',
    'soak_mappings.py': '708301538c24476e4d244efb16cc5027c193efd5',
    'soak_ret_context.py': 'eac5605150e51b9aec336277088e3981616ac28e',
    'verify_soak.py': 'e0c0321054c8be6510f190b33d07966aad8635aa',
}
ARCHIVES = {
    'ledger180': dict(run_id=40464561145, artifact_id=12715977074,
        sha256='2e7a8038509a073508bde33b6a9ad880a58e37b674fa371d8fc7d73d26dd4a13'),
    'tls_failure': dict(run_id=40464561031, artifact_id=12715657366,
        sha256='6dd5df1a0ccc7b3c2a87902cec3b0d61be76fcf959a29e94c7644e6489c4f689'),
}


def canon(value):
    return json.loads(json.dumps(value))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unpack(path, target, metadata):
    assert sha256(path) == metadata['sha256'], 'archive digest mismatch'
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None, 'archive CRC failure'
        assert len(archive.namelist()) == len(set(archive.namelist()))
        assert all(not Path(n).is_absolute() and '..' not in Path(n).parts
                   for n in archive.namelist()), 'unsafe ZIP path'
        archive.extractall(target)
    return {str(p.relative_to(target)): sha256(p)
            for p in sorted(target.rglob('*')) if p.is_file()}


def inspect_stage(folder, control, ledger, context, experiment):
    execution = json.loads((folder/'execution.json').read_text())
    target = context.proc_identity((folder/'target-before.stat').read_text())
    parent = context.proc_identity((folder/'tracer-before.stat').read_text())
    assert execution['exit_code'] == 0 and not execution['timed_out']
    assert not execution['cleanup_signals'] and execution['group_gone']
    assert execution['target_identity_verified']
    assert execution['target_identity'] == target and execution['tracer_identity'] == parent
    assert context.owned_groups(execution['process_group'], target, parent,
        (folder/'tracer-exe.txt').read_text(), Path(execution['command'][2])) == execution['owned_groups']
    assert not re.search(r'(?i)lost|dropped|error|failed',
                         (folder/'bpftrace-stderr.log').read_text())
    plan = json.loads((folder/'plan.json').read_text())
    symbols = ledger.CONTROL if control else context.SYMBOLS
    assert {k:f['symbol'] for k,f in plan['functions'].items()} == {
        str(k):v for k,v in symbols.items()}
    for kind, function in plan['functions'].items():
        assert context.ret_sites(function['disassembly'], function['address'],
            function['size']) == function['ret_offsets']
        tails = function.get('tail_exits', [])
        assert not tails or (kind == '1' and all(
            t['symbol'] == '_ZN6__tsan10SlotUnlockEPNS_11ThreadStateE' for t in tails))
        assert context.tail_sites(function['disassembly'], function['address'],
            function['size'], {t['target']:t['symbol'] for t in tails}) == tails
    parsed = ledger.parse((folder/'events.log').read_text(), plan, execution['expected_uid'])
    assert canon(parsed) == json.loads((folder/'context-audit.json').read_text())
    assert canon(parsed) == experiment['ledger']
    rows = ledger.audit_snapshots(folder, parsed, not control, control)
    assert canon(rows) == experiment['snapshots']
    return parsed, rows, dict(identity_verified=True, group_gone=True,
        timed_out=False, cleanup_signals=[], events=parsed['events'],
        calls=dict(Counter(c['call'] for c in parsed['calls'])),
        snapshots=len(rows), binary_sha256=plan['binary_sha256'])


def transition(before, after, calls):
    # Whole-VMA matching is deliberately strict. Changed bounds/generations
    # are not treated as the same allocation, even at the same address.
    signature = lambda v: (v['start'], v['end'], tuple(v['generations']))
    a = {signature(v):v for v in before['family']['unnamed_vmas']}
    b = {signature(v):v for v in after['family']['unnamed_vmas']}
    common = a.keys() & b.keys()
    stable = [k for k in common if a[k]['owner'] == b[k]['owner']
              and not a[k]['read_overlaps_mutation'] and not b[k]['read_overlaps_mutation']]
    mutations = [c for c in calls if before['read_end_monotonic_ns'] < c['end_ns']
                 <= after['read_end_monotonic_ns']]
    owners = sorted({b[k]['owner'] for k in stable})
    return dict(from_key=before['key'], to_key=after['key'],
        statm_rss_delta_bytes=after['rss']-before['rss'],
        family_rss_delta_bytes=after['family']['groups_rss_bytes'].get('observed_race_runtime',0)
            - before['family']['groups_rss_bytes'].get('observed_race_runtime',0),
        unresolved_rss_delta_bytes=after['family']['groups_rss_bytes'].get('unresolved',0)
            - before['family']['groups_rss_bytes'].get('unresolved',0),
        same_bounds_generations_owner_rss_delta_bytes={owner:sum(
            b[k]['rss']-a[k]['rss'] for k in stable if b[k]['owner']==owner) for owner in owners},
        new_or_changed_whole_vmas=[b[k] for k in sorted(b.keys()-a.keys())],
        removed_or_changed_whole_vmas=[a[k] for k in sorted(a.keys()-b.keys())],
        memory_syscalls=dict(Counter(c['call'] for c in mutations)),
        scope='endpoint mapping identity only, not object liveness or intermediate page residence')


def audit_ledger(root, ledger, context, verify, rollup):
    assert (root/'tracer-source.txt').read_text().strip() == TRACER
    info = (root/'bpftrace-info.txt').read_text()
    assert 'version: v0.21.2' in info and 'bfd: yes' in info and 'unsafe probe: no' in info
    assert re.search(r'^ALLOW_UNSAFE_PROBE:(BOOL|UNINITIALIZED)=OFF$',
        (root/'tracer-CMakeCache.txt').read_text(), re.M)
    folder = root/'experiment'
    exp = json.loads((folder/'experiment.json').read_text())
    assert exp['status']=='failed' and exp['duration']=='180s' and exp['pilot_only']
    assert exp['error']=='ValueError: active resource bound: rss'
    assert exp['stages']==['control_passed','mapping_audit_passed'] and 'acceptance' not in exp
    _, control_rows, control = inspect_stage(folder/'control',True,ledger,context,exp['control'])
    parsed, fine, pilot = inspect_stage(folder/'pilot',False,ledger,context,exp['pilot'])
    hashes={line.split()[1]:line.split()[0] for line in (root/'binary-sha256.txt').read_text().splitlines()}
    assert control['binary_sha256']==hashes['bin/ledger-control']
    assert pilot['binary_sha256']==hashes['bin/probe']
    native=folder/'pilot/native'; report=json.loads((native/'report.json').read_text());s=report['settings']
    assert CHECKOUT in report['build_info'] and 'vcs.modified=false' in report['build_info']
    assert '-race=true' in report['build_info'] and report['build_info']==exp['description']['build_info']
    assert (report['transport'],report['mode'],s['tls'],s['duration_seconds'],s['warmup_seconds'],
        s['sample_interval_seconds'],s['pool_min'],s['pool_max'],s['workers'],s['qps']) == (3,1,1,180,12,5,16,64,2,10)
    assert s['pid']==parsed['native_pid']
    events=verify.validate_events(native/'exchanges.jsonl.gz',report)
    assert events==exp['events']==1919
    verify.validate_engine_logs(native,folder/'pilot/native-stderr.log',64,3)
    try:
        verify.validate_report(report,True)
    except ValueError as error:
        assert str(error)=='active resource bound: rss'
    else:
        raise AssertionError('original resource failure disappeared')
    assert verify.ACTIVE['rss']==64*MIB
    raw_rollup=rollup.audit(native/'report.json')
    family_calls=ledger.prepare([dict(c,owner='observed_race_runtime' if c['contexts'] else 'unresolved')
                                 for c in parsed['calls']])
    capture=json.loads((folder/'pilot/snapshots.json').read_text())
    points={tuple([p['phase'],p['at_seconds']]):p for p in report['points']}
    all_rows=[]
    for rec, detailed in zip(capture['records'],fine):
        family=ledger.attribute(gzip.open(folder/'pilot'/rec['file'],'rt').read(),True,
            family_calls,rec['read_start_monotonic_ns'],rec['read_end_monotonic_ns'])
        assert sum(family['groups_rss_bytes'].values())==sum(detailed['groups_rss_bytes'].values())
        assert sum(v['rss'] for v in family['unnamed_vmas'])==sum(v['rss'] for v in detailed['unnamed_vmas'])
        point=points[tuple(rec['key'])]
        all_rows.append(dict(key=rec['key'],rss=point['resources']['rss'],
            resources={k:v for k,v in point['resources'].items() if k!='os_memory'},
            family=family,fine=detailed,read_end_monotonic_ns=rec['read_end_monotonic_ns']))
    warm=[x for x in all_rows if x['key'][0]=='warmup' and x['key'][1]>=s['warmup_seconds']/2]
    measured=[x for x in all_rows if x['key'][0]=='measured']
    baseline=max(warm,key=lambda x:x['rss']);peak=max(measured,key=lambda x:x['rss'])
    crossing=next(i for i,x in enumerate(measured) if x['rss']>baseline['rss']+64*MIB)
    selected=dict(baseline=baseline,first_measured=measured[0],before_crossing=measured[crossing-1],
        first_crossing=measured[crossing],after_crossing=measured[crossing+1],peak=peak,last_measured=measured[-1])
    assert peak['rss']-baseline['rss']==raw_rollup['statm_rss_delta']
    compact=[dict(key=x['key'],rss=x['rss'],family_groups=x['family']['groups_rss_bytes'],
        fine_groups=x['fine']['groups_rss_bytes']) for x in all_rows]
    ranges=[('baseline','peak'),('before_crossing','first_crossing'),
            ('first_crossing','after_crossing'),('peak','last_measured')]
    return dict(original_status=exp['status'],original_error=exp['error'],
        acceptance_status='failed',qualifies_24h=False,control=control,pilot=pilot,
        control_snapshots=control_rows,counts=report['counts'],warmup_counts=report['warmup_counts'],
        events=events,measured_seconds=report['measured_seconds'],
        budget=dict(allowance_bytes=64*MIB,baseline_rss=baseline['rss'],peak_rss=peak['rss'],
            delta_bytes=peak['rss']-baseline['rss'],excess_bytes=peak['rss']-baseline['rss']-64*MIB,
            first_crossing_load_seconds=measured[crossing]['key'][1],
            measured_first_last_delta_bytes=measured[-1]['rss']-measured[0]['rss']),
        rollup=raw_rollup,all_snapshot_groups=compact,selected=selected,
        transitions=[transition(selected[a],selected[b],parsed['calls']) for a,b in ranges],
        scope='same process whole-VMA request-origin lower bounds; smaps/statm non-atomic; '
            'no object/cache/leak conclusion; drained and after_stop have no external mapping coverage')


def audit_tls(root):
    report_path=root/'artifacts/positive/report.json'
    report=json.loads(report_path.read_text());rows=report['results']
    summary=json.loads((root/'artifacts/summary.json').read_text())
    assert len(summary['reports'])==1 and summary['reports'][0]['sha256']==sha256(report_path)
    provenance=json.loads((root/'bin/nodepass-original.provenance.json').read_text())
    assert provenance['source_commit']=='114345043d9608e1e24e783a270cde75193e4f42'
    assert provenance['source_modified'] is False
    assert provenance['binary_sha256']==report['binaries']['upstream']['sha256']
    assert CHECKOUT in report['binaries']['tunveo']['go_build_info']
    assert report['status']=='failed' and len(rows)==160
    assert Counter(x['status'] for x in rows)==Counter(passed=120,failed=40)
    seen=set();failures=[]
    for row in rows:
        assert row['pair_server_client']=='upstream/tunveo' and row['tls']==0
        cell=(row['transport'],row['mode'],row['pool']['min'],row['pool']['max'],row['iteration'])
        assert cell not in seen;seen.add(cell)
        assert row['phases']['cleanup']['status']=='passed'
        assert all(c['reaped'] and not c['forced_kill'] for c in row['cleanup'])
        assert row['commands'][0][0].endswith('/nodepass-original')
        if row['status']=='failed':
            assert row['transport']==3 and row['failed_phase']=='tunnel_handshake'
            server=(root/'artifacts/positive'/row['id']/'server.log').read_text()
            client=(root/'artifacts/positive'/row['id']/'client.log').read_text()
            panic='panic: runtime error: invalid memory address or nil pointer dereference' in server
            assert panic or 'Loading tunnel config: FLOW=-|MAX=' in server
            failures.append(dict(id=row['id'],transport=row['transport'],mode=row['mode'],
                pool=row['pool'],iteration=row['iteration'],error=row['error'],
                upstream_panic=panic,server_sha256=hashlib.sha256(server.encode()).hexdigest(),
                client_sha256=hashlib.sha256(client.encode()).hexdigest(),
                upstream_loaded_tls0='|TLS=0|TYPE=3' in server,
                panic_stack=server[server.index('panic:'):] if panic else None))
        else:
            assert row['transport'] in (0,1,2)
    assert seen=={(t,m,lo,hi,i) for t in range(4) for m in (1,2)
                  for lo,hi in ((2,8),(64,1024)) for i in range(1,11)}
    return dict(original_status='failed',positive_passed=120,positive_failed=40,
        failures=failures,upstream_panic_count=sum(x['upstream_panic'] for x in failures),
        provenance=provenance,binaries=report['binaries'],
        scope='this one failed shard only; other shard success is CI status, not independently re-audited here; '
            'effective_tls is the expected normalized value, not proof that upstream negotiated it')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scripts-dir',type=Path,default=Path('scripts'))
    parser.add_argument('--ledger-archive',type=Path,required=True)
    parser.add_argument('--tls-archive',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--summary',type=Path,help='Optional compact evidence for repository review')
    args=parser.parse_args()
    for name,expected in SOURCES.items():
        raw=(args.scripts_dir/name).read_bytes()
        assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==expected, name
    sys.path.insert(0,str(args.scripts_dir.resolve()))
    ledger=importlib.import_module('soak_mapping_ledger');context=importlib.import_module('soak_ret_context')
    verify=importlib.import_module('verify_soak');rollup=importlib.import_module('audit_soak_os_memory')
    with tempfile.TemporaryDirectory(prefix='pr29-readonly-') as temp:
        root=Path(temp)
        files={key:unpack(path,root/key,ARCHIVES[key]) for key,path in
            [('ledger180',args.ledger_archive),('tls_failure',args.tls_archive)]}
        result=dict(format_version=1,source_sha=SOURCE,checkout_sha=CHECKOUT,tree_sha=TREE,
            archives=ARCHIVES,pinned_source_blobs=SOURCES,original_file_sha256=files,
            ledger180=audit_ledger(root/'ledger180',ledger,context,verify,rollup),
            tls_failure=audit_tls(root/'tls_failure'),
            audit_status='verified_preserved_failures',qualifies_24h=False)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    if args.summary:
        compact=canon(result)
        for row in compact['ledger180']['selected'].values():
            row['fine']={'groups_rss_bytes':row['fine']['groups_rss_bytes']}
            row['family']={'groups_rss_bytes':row['family']['groups_rss_bytes']}
        for row in compact['ledger180']['control_snapshots']:
            row.pop('point',None)
        failed=compact['tls_failure']['failures']
        compact['tls_failure']['sample_upstream_panic_stack']=failed[0]['panic_stack']
        for row in failed:
            row.pop('panic_stack')
        args.summary.parent.mkdir(parents=True,exist_ok=True)
        args.summary.write_text(json.dumps(compact,indent=2,ensure_ascii=False)+'\n')
    print('Independent audit verified; original 180s RSS and TLS acceptance failures remain failed.')


if __name__=='__main__':
    main()
