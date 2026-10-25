#!/usr/bin/env python3
"""Local image smoke: read-only root, private mounted state, no child tunnels or push."""
import argparse,hashlib,os,http.client,json,subprocess,tempfile,time
from pathlib import Path
from verify_security import free_port

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();root=Path(__file__).resolve().parents[1];rows=[];report={'scope':'Linux amd64 container smoke only, host-loopback API, writable private state mount, read-only root, no registry push','results':rows}
 def docker(*args):return subprocess.check_output(['docker',*args],text=True,timeout=30).strip()
 def passed(name):rows.append({'case':name,'status':'passed'})
 cid=None;key=None
 try:
  report['image_id']=docker('image','inspect','--format','{{.Id}}',a.image)
  version=docker('run','--rm','--network','none','--read-only',a.image,'version');assert version.startswith('tunveo-integration-') and 'linux/amd64' in version;report['version']=version;passed('version-read-only-no-network')
  with tempfile.TemporaryDirectory(prefix='tunveo-container-') as temp:
   port=free_port();cid=docker('run','-d','--user',f'{os.getuid()}:{os.getgid()}','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--network','host','--mount',f'type=bind,source={temp},target=/gob',a.image,f'master://127.0.0.1:{port}?log=none')
   def api(path,auth=False):
    c=http.client.HTTPConnection('127.0.0.1',port,timeout=1);c.request('GET','/api/v1/'+path,headers={'X-API-Key':key} if auth else {});r=c.getresponse();body=r.read();status=r.status;c.close();return status,body
   deadline=time.monotonic()+10
   while True:
    try:
     if api('openapi.json')[0]==200:break
    except OSError:pass
    assert time.monotonic()<deadline;time.sleep(.05)
   passed('master-starts-with-state-volume')
   assert api('instances')[0]==401;passed('authentication-required')
   key=docker('exec',cid,'/tunveo','api-key','--state','/gob/tunveo.gob');assert len(key)==32 and api('instances',True)[0]==200;passed('authenticated-api')
   report_text=docker('exec',cid,'/tunveo','state','inspect','--state','/gob/tunveo.gob');assert key not in report_text and json.loads(report_text)['api_key_present'];passed('offline-inspect-in-image')
   dest=Path(temp)/'licenses';subprocess.run(['docker','cp',cid+':/usr/share/licenses/tunveo',str(dest)],check=True,capture_output=True,timeout=10)
   for name in ['LICENSE','NOTICE']:assert (dest/name).read_bytes()==(root/name).read_bytes()
   for name in ['tcp','quic','websocket','http2']:assert (dest/name/'LICENSE').read_bytes()==(root/'internal/tunnelpool'/name/'LICENSE').read_bytes()
   passed('all-six-license-files')
   docker('stop','-t','8',cid);assert docker('inspect','--format','{{.State.ExitCode}}',cid)=='0';logs=docker('logs',cid);assert 'panic:' not in logs and key not in logs;passed('clean-stop-no-key-log')
   docker('rm',cid);cid=None
  report['status']='passed'
 except BaseException as e:report['status']='failed';report['error_type']=type(e).__name__;raise
 finally:
  if cid:subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=15)
  a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'passed':len(rows)}))
if __name__=='__main__':main()
