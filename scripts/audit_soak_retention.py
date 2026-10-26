#!/usr/bin/env python3
"""Audit isolated post-stop GC/scavenge phases without changing load acceptance."""
import argparse
import gzip
import json
import math
from pathlib import Path
import soak_mappings as mappings
import audit_soak_os_memory as rollup


def validate_retention_points(r):
    seconds=r['settings']['post_stop_observe_seconds']
    force=r['settings']['diagnostic_go_scavenge']
    if not math.isfinite(seconds) or not 5<=seconds<=600:
        raise ValueError('invalid diagnostic horizon')
    points=r['post_stop_observation']
    gc=[p for p in points if p['phase']=='poststop_gc']
    scavenged=[p for p in points if p['phase']=='poststop_go_scavenge']
    if len(gc)<2 or gc[0]['at_seconds']>5 or not seconds<=gc[-1]['at_seconds']<=seconds+15:
        raise ValueError('incomplete GC-sampled post-stop window')
    if len(scavenged)!=(1 if force else 0) or points!=gc+scavenged:
        raise ValueError('scavenge not isolated after complete observation')
    if any(not 0<b['at_seconds']-a['at_seconds']<=10 for a,b in zip(gc,gc[1:])):
        raise ValueError('post-stop sample gap')
    if scavenged and (scavenged[0]['at_seconds']<gc[-1]['at_seconds'] or not scavenged[0]['go_scavenge_seconds']>0):
        raise ValueError('invalid scavenge action timing')
    return gc,scavenged


def audit(folder):
    original=mappings.audit(folder)
    r=json.loads((folder/'pilot/native/report.json').read_text())
    capture=json.loads((folder/'mapping-report.json').read_text())
    gc,scavenged=validate_retention_points(r)
    if r['counts']['failed'] or r['counts']['dropped']:
        raise ValueError('post-stop diagnostics do not excuse failed load')
    records={mappings.point_key(p):p for p in capture['samples']}
    evidence_hash=mappings.load_evidence_hash(r)
    for p in r['post_stop_observation']:
        os=p['resources']['os_memory']
        if os.get('error') or rollup.parse_rollup(os['smaps_rollup_raw'])!=os['bytes']:
            raise ValueError('post-stop rollup mismatch')
        record=records[mappings.point_key(p)]
        if record.get('load_evidence_sha256')!=evidence_hash:
            raise ValueError('load envelope or original after_stop was rewritten')
    handshake=None
    if r['settings'].get('post_stop_observer_ack'):
        handshake=json.loads((folder/'pilot/native/post-stop-observer-ack.json').read_text())
        record=records[mappings.point_key(gc[-1])]
        if (handshake['phase'],handshake['at_seconds'])!=mappings.point_key(gc[-1]) or handshake['mapping_sha256']!=record['sha256'] or handshake['load_evidence_sha256']!=evidence_hash:
            raise ValueError('observer acknowledgment does not match completed pre-scavenge evidence')
    indices=[gc[0],gc[-1]]+scavenged
    selected=[]
    for p in indices:
        record=records[mappings.point_key(p)]
        if not 0<=record['checkpoint_age_seconds']<=.1 or (record['read_finished_ns']-record['read_started_ns'])/1e9>.1:
            raise ValueError('post-stop maps too far from checkpoint')
        vmas=mappings.parse_smaps(gzip.open(folder/record['file'],'rt').read(),capture['race'])['mappings']
        groups={}
        for vma in vmas:
            key=vma['category']
            if key=='other_anonymous':key=vma['path'] or 'unnamed_anonymous'
            groups[key]=groups.get(key,0)+vma['bytes']['Rss']
        s=p['resources']
        selected.append(dict(phase=p['phase'],at_seconds=p['at_seconds'],statm_rss=s['rss'],
                             heap_alloc=s['heap_alloc'],heap_released=s['heap_released'],heap_sys=s['heap_sys'],
                             groups_rss_bytes=groups,checkpoint_age_seconds=record['checkpoint_age_seconds']))
    def delta(a,b):
        return dict(statm_rss=b['statm_rss']-a['statm_rss'],heap_released=b['heap_released']-a['heap_released'],
                    heap_alloc=b['heap_alloc']-a['heap_alloc'],groups_rss_bytes={k:b['groups_rss_bytes'].get(k,0)-a['groups_rss_bytes'].get(k,0) for k in sorted(a['groups_rss_bytes'].keys()|b['groups_rss_bytes'].keys())})
    return dict(active_acceptance=original['status'],active_error=original['error'],active_rss_delta=original['statm_rss_delta'],
                audited_events=original['audited_events'],load_evidence_sha256=evidence_hash,
                observer_acknowledgment=handshake,gc_sampled_seconds=gc[-1]['at_seconds'],gc_samples=len(gc),selected=selected,
                gc_window_delta=delta(selected[0],selected[1]),
                go_scavenge_delta=delta(selected[1],selected[2]) if scavenged else None,
                scope='post-stop repeatedGC observation, then explicit Go-scavenge; separate clocks/reads, not natural idle; never rewrites active envelope, after_stop, budgets, or failed result')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('artifacts',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.write_text(json.dumps(audit(a.artifacts),indent=2)+'\n')


if __name__=='__main__':main()
