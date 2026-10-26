#!/usr/bin/env python3
"""Replay the self-endpoint allocation against an immutable diagnostic runner."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from unittest import mock
from probe_selfecho_fixture import ForcedSourceCollision


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ref',required=True)
    p.add_argument('--mode',choices=('original','fixed'),required=True)
    p.add_argument('--repeat',type=int,default=10)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();root=Path(__file__).resolve().parents[1]
    commit=subprocess.check_output(['git','rev-parse',a.ref],cwd=root,text=True).strip()
    raw=subprocess.check_output(['git','show',commit+':scripts/verify_forwarding.py'],cwd=root)
    rows=[]
    with tempfile.TemporaryDirectory(prefix='tunveo-probe-selfecho-') as temp:
        path=Path(temp)/'runner.py';path.write_bytes(raw)
        spec=importlib.util.spec_from_file_location('diagnostic_replay',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        for udp in (False,True):
            for i in range(a.repeat):
                fixture=ForcedSourceCollision(udp);echoed=False
                with mock.patch.object(module.socket,'socket',fixture.socket):
                    try:module.exchange(fixture.target[1],udp=udp,timeout=.5);echoed=True
                    except OSError:pass
                assert all(s.closed for s in fixture.sockets)
                if a.mode=='original':
                    assert echoed and len(fixture.sockets)==1 and fixture.sockets[0].local==fixture.sockets[0].peer
                else:
                    assert not echoed and len(fixture.sockets)>=2 and fixture.sockets[0].sends==0
                    assert sum(s.sends for s in fixture.sockets)<=1
                rows.append({'protocol':'udp' if udp else 'tcp','iteration':i+1,'echoed_without_listener':echoed,'source_allocations':len(fixture.sockets),'application_sends':sum(s.sends for s in fixture.sockets),'endpoints':[{'local':s.local,'peer':s.peer} for s in fixture.sockets]})
    report={'source_commit':commit,'source_sha256':hashlib.sha256(raw).hexdigest(),'scope':'real loopback sockets, forced source allocation; no listener or engine; not attribution of the historical uninstrumented cell','mode':a.mode,'status':'reproduced' if a.mode=='original' else 'passed','results':rows}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'mode':a.mode,'status':report['status'],'cases':len(rows)}))


if __name__=='__main__':main()
