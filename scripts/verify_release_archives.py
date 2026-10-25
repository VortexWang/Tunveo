#!/usr/bin/env python3
"""Check all eight snapshot archives, platform headers, notices, runbook and checksums."""
import argparse,hashlib,json,os,struct,subprocess,tarfile,tempfile,zipfile
from pathlib import Path

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dist',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();root=Path(__file__).resolve().parents[1];rows=[];report={'scope':'snapshot packaging only; Linux amd64 native smoke, other targets header/build verification','results':rows}
 try:
  checks={line.split()[-1]:line.split()[0] for line in (a.dist/'checksums.txt').read_text().splitlines()}
  licenses=['LICENSE','NOTICE',*[f'internal/tunnelpool/{n}/LICENSE' for n in ['tcp','quic','websocket','http2']]]
  required=[*licenses,'docs/state-migration.md','docs/migration.md','README.md']
  for system in ['darwin','freebsd','linux','windows']:
   for arch in ['amd64','arm64']:
    suffix='zip' if system=='windows' else 'tar.gz';matches=list(a.dist.glob(f'tunveo_*_{system}_{arch}.{suffix}'));assert len(matches)==1,(system,arch,matches);archive=matches[0]
    digest=hashlib.sha256(archive.read_bytes()).hexdigest();assert checks[archive.name]==digest
    if suffix=='zip':
     with zipfile.ZipFile(archive) as z:members={n:z.read(n) for n in z.namelist() if not n.endswith('/')}
    else:
     with tarfile.open(archive) as tar:members={m.name:tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}
    assert all(name in members for name in required),(archive.name,'missing required files')
    assert not any(n.endswith('.gob') or n.startswith(('gob/','artifacts/')) for n in members)
    for name in licenses:assert members[name]==(root/name).read_bytes(),(archive.name,name)
    binary='tunveo.exe' if system=='windows' else 'tunveo';data=members[binary]
    if system in ('linux','freebsd'):
     assert data[:4]==b'\x7fELF' and struct.unpack_from('<H',data,18)[0]=={'amd64':62,'arm64':183}[arch]
     if system=='freebsd':assert data[7]==9
    elif system=='darwin':assert data[:4]==b'\xcf\xfa\xed\xfe' and struct.unpack_from('<I',data,4)[0]=={'amd64':0x1000007,'arm64':0x100000c}[arch]
    else:
     offset=struct.unpack_from('<I',data,60)[0];assert data[:2]==b'MZ' and data[offset:offset+4]==b'PE\0\0';assert struct.unpack_from('<H',data,offset+4)[0]=={'amd64':0x8664,'arm64':0xaa64}[arch]
    row={'platform':system+'/'+arch,'archive':archive.name,'sha256':digest,'status':'passed','licenses':len(licenses),'native_executed':False}
    if system=='linux' and arch=='amd64':
     with tempfile.TemporaryDirectory(prefix='tunveo-package-') as temp:
      path=Path(temp)/binary;path.write_bytes(data);path.chmod(0o755);v=subprocess.check_output([str(path),'version'],text=True,timeout=3);assert v.startswith('tunveo-') and 'SNAPSHOT' in v.upper(),v
      help_text=subprocess.check_output([str(path),'help'],text=True,timeout=3);assert 'state' in help_text
      row.update(native_executed=True,version=v.strip())
    rows.append(row)
  assert len([p for p in a.dist.iterdir() if p.name.endswith(('.tar.gz','.zip'))])==8
  report['status']='passed'
 except BaseException as e:report['status']='failed';report['error_type']=type(e).__name__;raise
 finally:
  a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'archives':len(rows)}))
if __name__=='__main__':main()
