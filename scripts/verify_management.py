#!/usr/bin/env python3
"""Loopback-only management HTTP/SSE process regression; synthetic local state."""
import argparse,datetime,hashlib,http.client,json,os,shutil,subprocess,tempfile,time
from pathlib import Path
from verify_security import free_port,wait_ready,stop

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();binary=a.binary.resolve()
 result={'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'helper_sha256':hashlib.sha256(Path(__file__).with_name('verify_security.py').read_bytes()).hexdigest(),'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'loopback, temporary master state; keys held only in memory; no child instances created','results':[]}
 def passed(name,**details):result['results'].append({'case':name,'status':'passed',**details})
 try:
  with tempfile.TemporaryDirectory(prefix='tunveo-management-') as temp:
   local=Path(temp)/'tunveo';shutil.copy2(binary,local);port=free_port();env={k:v for k,v in os.environ.items() if not k.startswith(('NP_','TUNVEO_'))}
   proc=subprocess.Popen([str(local),f'master://127.0.0.1:{port}?log=debug'],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
   sockets=[];secrets=[]
   def call(method,path,key=None,body=None,chunked=False):
    conn=http.client.HTTPConnection('127.0.0.1',port,timeout=3);headers={} if key is None else {'X-API-Key':key}
    if body is not None:headers['Content-Type']='application/json'
    conn.request(method,path,body=body,headers=headers,encode_chunked=chunked);response=conn.getresponse();data=response.read();status=response.status;conn.close();return status,data
   def subscribe(key):
    conn=http.client.HTTPConnection('127.0.0.1',port,timeout=3);conn.request('GET','/api/v1/events',headers={'X-API-Key':key});r=conn.getresponse();sockets.append(conn);return conn,r
   try:
    wait_ready(proc,port)
    key=subprocess.check_output([str(local),'api-key','--state',str(Path(temp)/'gob/tunveo.gob')],env=env,text=True,timeout=3).strip();secrets.append(key)
    for path in ['/api/v1/instances','/api/v1/info','/api/v1/tcping','/api/v1/events','/api/v2']:
     for mode,k in [('missing',None),('wrong','wrong-fixture-key')]:
      status,_=call('GET',path,k);assert status==401;passed('authentication/'+path+'/'+mode,status=status)
    for path in ['/api/v1/docs','/api/v1/openapi.json']:
     status,_=call('GET',path);assert status==200;passed('public/'+path,status=status)
    initialize=json.dumps({'jsonrpc':'2.0','id':1,'method':'initialize'}).encode()
    status,data=call('POST','/api/v2',key,initialize);assert status==200 and 'result' in json.loads(data);passed('mcp/initialize')
    status,data=call('POST','/api/v2',key,initialize+b' {}');assert 'error' in json.loads(data);passed('mcp/trailing-value-rejected')
    status,_=call('POST','/api/v1/info',key,b'{"alias":"x"} {}');assert status==400;passed('rest/trailing-value-rejected')
    big=json.dumps({'jsonrpc':'2.0','id':1,'method':'initialize','padding':'x'*((1<<20)+1)}).encode()
    for chunked in [False,True]:
     status,_=call('POST','/api/v2',key,iter([big]) if chunked else big,chunked);assert status==413;passed('body/'+('chunked' if chunked else 'content-length'),status=status)
    active=[]
    for _ in range(32):
     conn,r=subscribe(key);assert r.status==200;assert r.readline().startswith(b'retry:');assert r.readline()==b'\n';active.append((conn,r))
    status,_=call('GET','/api/v1/events',key);assert status==429;passed('sse/capacity-32',status=status)
    # Rotation disconnects existing subscribers and does not broadcast the new key.
    status,data=call('PATCH','/api/v1/instances/********',key,b'{"action":"restart"}');assert status==200;next_key=json.loads(data)['url'];assert next_key!=key;secrets.append(next_key)
    for conn,r in active:
     tail=r.read();assert key.encode() not in tail and next_key.encode() not in tail;r.close();conn.close()
    passed('sse/rotation-disconnect-no-key')
    status,_=call('GET','/api/v1/info',key);assert status==401;passed('rotation/old-key-rejected')
    conn,r=subscribe(next_key);assert r.status==200;r.close();conn.close();passed('rotation/new-key-sse')
   finally:
    for conn in sockets:conn.close()
    logs=stop(proc)
   assert 'DATA RACE' not in logs and 'panic:' not in logs and all(s not in logs for s in secrets)
   passed('cleanup',exit_code=0,forced_kill=False,raw_log_safe=True)
  result['status']='passed'
 except BaseException as e:
  result['status']='failed';result['error_type']=type(e).__name__;raise
 finally:
  a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'passed':len(result['results'])}))
if __name__=='__main__':main()
