#!/usr/bin/env python3
"""Actual race master + loopback-only managed children, concurrent metadata and lifecycle."""
import argparse,concurrent.futures,datetime,hashlib,http.client,json,os,shutil,socket,subprocess,tempfile,time
from pathlib import Path
from verify_security import free_port,wait_ready,stop

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();binary=a.binary.resolve();rows=[]
 report={'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'helper_sha256':hashlib.sha256(Path(__file__).with_name('verify_security.py').read_bytes()).hexdigest(),'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'race master and actual managed children; synthetic credentials, isolated state, loopback listeners; no external targets contacted','results':rows}
 def passed(case,**fields):rows.append({'case':case,'status':'passed',**fields})
 try:
  with tempfile.TemporaryDirectory(prefix='tunveo-master-life-') as temp:
   local=Path(temp)/'tunveo';shutil.copy2(binary,local);port=free_port()
   env={k:v for k,v in os.environ.items() if not k.startswith(('NP_','TUNVEO_'))};env.update(NP_REPORT_INTERVAL='50ms',NP_RELOAD_INTERVAL='200ms',NP_SHUTDOWN_TIMEOUT='8s')
   proc=subprocess.Popen([str(local),f'master://127.0.0.1:{port}?log=debug'],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
   # A reader owns the pipe throughout; frequent child checkpoints cannot fill it.
   import threading,re
   output=[];active={};reaped=set();observations_lock=threading.Lock()
   def capture():
    for line in proc.stdout:
     output.append(line)
     with observations_lock:
      started=re.search(r'Instance starting:.*\[([0-9a-f]+)\] pid=(\d+)',line)
      ended=re.search(r'Instance reaped \[([0-9a-f]+)\] pid=(\d+) success=(true|false)',line)
      if started:active[int(started[2])]=started[1];history.add(int(started[2]))
      if ended:active.pop(int(ended[2]),None);reaped.add(int(ended[2]))
   reader=threading.Thread(target=capture);reader.start()
   key=None;children=[];child_ports=[];history=set()
   def call(method,path,body=None):
    c=http.client.HTTPConnection('127.0.0.1',port,timeout=4);headers={'X-API-Key':key} if key else {}
    data=None if body is None else json.dumps(body).encode();c.request(method,'/api/v1/'+path,data,headers);r=c.getresponse();payload=r.read();status=r.status;c.close();return status,json.loads(payload) if payload else None
   def pids():
    with observations_lock:found=set(active)
    history.update(found);return found
   def until(predicate):
    deadline=time.monotonic()+6
    while not predicate():
     if proc.poll() is not None or time.monotonic()>=deadline:
      report['last_observation']={'master_pid':proc.pid,'pids':sorted(pids()),'states':[call('GET','instances/'+i)[1].get('status') for i in children]}
      raise AssertionError('lifecycle observation deadline')
     time.sleep(.025)
   def status(i):return call('GET','instances/'+i)[1]['status']
   try:
    wait_ready(proc,port)
    key=subprocess.check_output([str(local),'api-key','--state',str(Path(temp)/'gob/tunveo.gob')],env=env,text=True,timeout=3).strip()
    for n in range(2):
     child_port=free_port();target_port=free_port();child_ports.extend([child_port,target_port])
     code,data=call('POST','instances',{'alias':f'child-{n}','url':f'server://fixture-child-key@127.0.0.1:{child_port}/127.0.0.1:{target_port}?mode=1&tls=0&log=debug'})
     assert code==201;children.append(data['id'])
    until(lambda:len(pids())==2 and all(status(i)=='running' for i in children));passed('two-managed-children',count=2)
    def metadata(worker):
     for n in range(30):
      i=children[(worker+n)%2]
      code,_=call('PATCH','instances/'+i,{'alias':f'worker-{worker}-{n}','meta':{'tags':{'revision':str(n)}}});assert code==200
      code,data=call('GET','instances/'+i);assert code==200 and isinstance(data['meta']['tags'],dict)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(metadata,range(4)))
    assert (Path(temp)/'gob/tunveo.gob.backup').exists();passed('logs-metadata-json-backup-overlap',patches=120,reads=120)
    before=pids();code,_=call('PATCH','instances/'+children[0],{'action':'restart'});assert code==200
    until(lambda:len(pids())==2 and pids()!=before and status(children[0])=='running');time.sleep(.2);assert status(children[0])=='running';passed('restart-new-generation')
    before=pids()
    def stop_child(_):assert call('PATCH','instances/'+children[0],{'action':'stop'})[0]==200
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(stop_child,range(8)))
    until(lambda:status(children[0])=='stopped' and len(pids())==1);passed('coalesced-stop-and-reap',requests=8)
    assert call('PATCH','instances/'+children[0],{'action':'start'})[0]==200
    until(lambda:len(pids())==2 and status(children[0])=='running');passed('start-after-reap')
    assert call('DELETE','instances/'+children[0])[0]==204
    until(lambda:len(pids())==1);assert call('GET','instances/'+children[0])[0]==404;passed('delete-no-resurrection')
   finally:
    if proc.poll() is None:proc.terminate()
    try:proc.wait(timeout=10)
    except subprocess.TimeoutExpired:proc.kill();proc.wait();raise AssertionError('master required forced kill')
    reader.join(timeout=2);assert not reader.is_alive()
    logs=''.join(output)
    log_path=a.output.with_suffix('.log');log_path.parent.mkdir(parents=True,exist_ok=True);log_path.write_text(logs.replace(key,'[TEST-API-KEY]') if key else logs)
    report['process_log']=log_path.name
    report['raw_key_log_observed']=bool(key and key in logs)
   logs=''.join(output);assert proc.returncode==0 and 'DATA RACE' not in logs and 'panic:' not in logs and 'Instance force killed' not in logs and (key is None or key not in logs)
   assert history.issubset(reaped), 'missing sole-Wait reap observation'
   report['children_seen']=sorted(history);report['children_reaped']=sorted(reaped);report['pid_observation']='parent startup and sole cmd.Wait completion records'
   passed('master-graceful-shutdown',exit_code=0,forced_kill=False,race_observed=False)
   # Persisted auto-start entries must not launch before a successful API bind.
   with socket.socket() as blocker:
    blocker.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);blocker.bind(('127.0.0.1',port));blocker.listen()
    blocked=subprocess.run([str(local),f'master://127.0.0.1:{port}?log=debug'],env=env,capture_output=True,text=True,timeout=4)
   assert 'bind failed' in blocked.stdout+blocked.stderr and 'Instance starting:' not in blocked.stdout+blocked.stderr
   passed('bind-failure-no-autostart')
  report['status']='passed'
 except BaseException as e:report['status']='failed';report['error_type']=type(e).__name__;raise
 finally:
  a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'passed':len(rows)}))
if __name__=='__main__':main()
