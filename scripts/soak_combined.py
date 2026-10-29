#!/usr/bin/env python3
"""Compare aligned-call tracing with and without page observation, in fresh processes."""
import argparse,json,os,subprocess
from pathlib import Path
import soak_aligned_calls as aligned
import soak_pagemap as page

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for n in ('binary','aligned-control','page-control','tracer','artifacts'):ap.add_argument('--'+n,type=Path,required=True)
    a=ap.parse_args();a.artifacts.mkdir(parents=True,exist_ok=False)
    result=dict(status='failed',qualifies_24h=False,rss_budget=67108864,historical_failures_retained=True,stages=[])
    try:
        os.environ['BPFTRACE_STRLEN']='256'
        if os.sysconf('SC_PAGE_SIZE')!=4096 or aligned.direct.sha(a.binary.read_bytes())!=aligned.direct.BINARY_SHA:raise ValueError('frozen ELF/page size required')
        folder=a.artifacts/'aligned-control'
        parsed=aligned.context.launch(a.aligned_control,folder,aligned.symbols(False),[],60,a.tracer,program_builder=aligned.program,auditor=aligned.audit)
        aligned.control_check(parsed,[json.loads(s) for s in (folder/'native-stdout.log').read_text().splitlines()]);result['aligned-control']=parsed;result['stages'].append('aligned_control_passed')
        for mode in ('disabled','enabled'):
            folder=a.artifacts/('page-control-'+mode);collector=page.Collector(folder,a.page_control,control=True)
            parsed=page.life.context.launch(a.page_control,folder,{1:'control_site'},[str(folder.resolve()),mode],90,a.tracer,program_builder=page.life.program,auditor=page.life.parse,poll_hook=collector)
            rows=page.life.snapshots(folder,parsed,True);pages=page.analyze(folder,parsed);page.validate_control(folder,parsed,rows,pages,mode)
            result['page-control-'+mode]=dict(ledger=parsed,snapshots=rows,pages=pages);result['stages'].append(mode+'_control_passed')
        # ABBA reduces order bias; each fresh process retains its own original baseline.
        for i,observe in enumerate((False,True,True,False)):
            name=f'{i+1}-'+('page' if observe else 'no-page');folder=a.artifacts/name;native=(folder/'native').resolve()
            collector=page.Collector(folder,a.binary,retained=True) if observe else aligned.retention.Collector(folder,a.binary)
            args=['--transport','3','--mode','1','--duration','180s','--warmup','12s','--sample-interval','5s','--workers','2','--qps','10','--pool-min','16','--pool-max','64','--artifacts',str(native),'--post-stop-observe','120s','--diagnostic-go-scavenge','--post-stop-observer-ack']
            parsed=aligned.context.launch(a.binary,folder,aligned.symbols(),args,450,a.tracer,program_builder=aligned.program,auditor=aligned.audit,poll_hook=collector)
            rows=aligned.lifecycle.snapshots(folder,parsed);report=json.loads((native/'report.json').read_text());stage=dict(ledger=parsed,snapshots=rows,errors=[],page_observation=observe);result[name]=stage
            if report['settings']['pid']!=parsed['native_pid'] or 'vcs.revision='+aligned.direct.REVISION not in report['build_info']:raise ValueError('native report identity mismatch')
            stage['business_events']=aligned.verify.validate_events(native/'exchanges.jsonl.gz',report);aligned.verify.validate_engine_logs(native,folder/'native-stderr.log',64,3)
            if observe:stage['pages']=page.analyze(folder,parsed,{page.life.LABEL,aligned.LABEL})
            try:stage['resources']=aligned.verify.validate_report(report,True)
            except ValueError as e:
                message=str(e)
                if not (message.startswith('active resource bound: ') or message.startswith('resource did not return: ')):raise
                stage['errors'].append(message)
            result['stages'].append(name+'_evidence_complete')
        result['status']='diagnostic_passed' if all(not result[f'{i+1}-'+('page' if v else 'no-page')]['errors'] for i,v in enumerate((False,True,True,False))) else 'failed'
    except (ValueError,KeyError,OSError,AssertionError,subprocess.SubprocessError) as e:result['error']=type(e).__name__+': '+str(e)
    finally:
        result['files']={str(f.relative_to(a.artifacts)):aligned.direct.sha(f.read_bytes()) for f in a.artifacts.rglob('*') if f.is_file() and f.name!='experiment.json'};aligned.direct.dump(a.artifacts/'experiment.json',result)
    return int(result['status']!='diagnostic_passed')
if __name__=='__main__':raise SystemExit(main())
