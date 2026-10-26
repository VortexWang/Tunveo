#!/usr/bin/env python3
"""Summarize complete and partial TLS reports without relabeling failed cells."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifacts', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    reports = []
    for path in sorted(a.artifacts.glob('*/report.json')):
        raw = path.read_bytes()
        r = json.loads(raw)
        rows = r['results']
        failed = [{k: x[k] for k in ('id','pair_server_client','tls','effective_tls','identity','transport','mode','pool','iteration','negative','status','failed_phase','error') if k in x} for x in rows if x['status'] != 'passed']
        reports.append({'report':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'status':r['status'],'settings':r['settings'],'binaries':r['binaries'],'counts':dict(Counter(x['status'] for x in rows)),'observed_cells':len(rows),'failures':failed})
    result = {'scope':'TLS 0/1/2 loopback, 4 transports, 2 flows, 2 capacities, 3 pairings; explicit-IP baseline plus maintained-peer default-IP/explicit-DNS identities; CA/name/expiry rejection controls','reports':reports}
    result['all_observed_passed'] = bool(reports) and all(r['status']=='passed' for r in reports)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    # JSON is also in the job log so it remains reviewable through the connector.
    print('TLS_SUMMARY='+json.dumps(result))


if __name__=='__main__':main()
