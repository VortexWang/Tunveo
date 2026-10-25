#!/usr/bin/env python3
"""Offline GOB transfer, rollback and real original/current master compatibility.

Fixtures use the original v1.17.0 Instance/Meta/Peer declarations and exact
SaveStateToPath method. Original runtime is loopback-only, no auto-start rows.
"""
import argparse,datetime,hashlib,http.client,io,json,os,re,shutil,subprocess,tarfile,tempfile,time
from pathlib import Path
from verify_security import free_port,wait_ready,stop

ORIGINAL='114345043d9608e1e24e783a270cde75193e4f42'
KEY='0123456789abcdef0123456789abcdef'

def method(source,name):
 start=source.index('func (m *Master) '+name+'(');brace=source.index('{',start);depth=1;end=brace+1
 while depth:
  if source[end]=='{':depth+=1
  elif source[end]=='}':depth-=1
  end+=1
 return source[start:end]

def fixture_source(root):
 types=subprocess.check_output(['git','show',ORIGINAL+':internal/master/types.go'],cwd=root,text=True)
 state=subprocess.check_output(['git','show',ORIGINAL+':internal/master/state.go'],cwd=root,text=True)
 defs='\n'.join(re.search(r'type '+name+r' struct \{.*?\n\}',types,re.S).group(0) for name in ['Instance','Meta','Peer'])
 code='''package main
import("context";"encoding/gob";"encoding/json";"fmt";"os";"os/exec";"path/filepath";"sync";"time")
type Master struct{StateMu sync.Mutex;Instances sync.Map}
'''+defs+'\n'+method(state,'SaveStateToPath')+'''
func main(){
 if os.Args[1]=="read"{f,e:=os.Open(os.Args[2]);if e!=nil{panic(e)};defer f.Close();var rows map[string]*Instance;if e=gob.NewDecoder(f).Decode(&rows);e!=nil{panic(e)};json.NewEncoder(os.Stdout).Encode(rows);return}
 m:=&Master{}
 root:=&Instance{ID:"********",Alias:"fixture-master",URL:"0123456789abcdef0123456789abcdef",Config:"abcdef0123456789abcdef0123456789ab",Meta:Meta{Tags:map[string]string{}}}
 m.Instances.Store(root.ID,root)
 for n:=1;n<=2;n++{role:="server";if n==2{role="client"};id:=fmt.Sprintf("%08x",n);url:=fmt.Sprintf("%s://fixture-child@127.0.0.1:12345/127.0.0.1:23456?mode=1&tls=0",role);m.Instances.Store(id,&Instance{ID:id,Alias:"中文 fixture",Type:role,Status:"stopped",URL:url,Config:url,Meta:Meta{Peer:Peer{SID:"peer",Type:role,Alias:"配对"},Tags:map[string]string{"owner":"fixture"}},TCPRX:uint64(1)<<63+123,TCPTX:^uint64(0),UDPRX:9007199254740993,UDPTX:9})}
 switch os.Args[3]{
 case "no-key":m.Instances.Delete("********")
 case "invalid-id":m.Instances.Store("wrong",&Instance{ID:"different",URL:"server://127.0.0.1:1/x"})
 case "invalid-url":m.Instances.Store("invalid",&Instance{ID:"invalid",URL:"bad://fixture"})
 case "quota":for n:=3;n<=1025;n++{id:=fmt.Sprintf("%08x",n);m.Instances.Store(id,&Instance{ID:id,Type:"server",URL:"server://127.0.0.1:12345/127.0.0.1:23456"})}
 case "restart":i,_:=m.Instances.Load("00000001");i.(*Instance).Restart=true
 }
 if e:=m.SaveStateToPath(os.Args[2]);e!=nil{panic(e)}
}
'''
 return code,{'original_commit':ORIGINAL,'types_file_sha256':hashlib.sha256(types.encode()).hexdigest(),'save_file_sha256':hashlib.sha256(state.encode()).hexdigest(),'helper_source_sha256':hashlib.sha256(code.encode()).hexdigest()}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',required=True,type=Path);p.add_argument('--upstream',type=Path);p.add_argument('--go',required=True);p.add_argument('--output',required=True,type=Path);a=p.parse_args();root=Path(__file__).resolve().parents[1];binary=a.binary.resolve();rows=[]
 report={'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'support_sha256':hashlib.sha256(Path(__file__).with_name('verify_security.py').read_bytes()).hexdigest(),'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'operator-owned synthetic GOB, isolated files, loopback original/current masters, Restart=false runtime oracles, no child processes','results':rows}
 def passed(case,**details):rows.append({'case':case,'status':'passed',**details})
 env={k:v for k,v in os.environ.items() if not k.startswith(('NP_','TUNVEO_'))};env.update(GOTOOLCHAIN='local',NP_RELOAD_INTERVAL='1h')
 try:
  with tempfile.TemporaryDirectory(prefix='tunveo-migrate-') as temp:
   folder=Path(temp);code,provenance=fixture_source(root);report['fixture']=provenance;helper=folder/'legacy-helper';(folder/'fixture.go').write_text(code)
   subprocess.run([a.go,'build','-trimpath','-o',str(helper),str(folder/'fixture.go')],cwd=folder,env=env,check=True,capture_output=True,timeout=60)
   upstream=a.upstream.resolve() if a.upstream else folder/'nodepass-original'
   if not a.upstream:
    checkout=folder/'original';checkout.mkdir();archive=subprocess.check_output(['git','archive',ORIGINAL],cwd=root)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:tar.extractall(checkout,filter='data')
    subprocess.run([a.go,'build','-trimpath','-o',str(upstream),'./cmd/nodepass'],cwd=checkout,env=env,check=True,capture_output=True,timeout=240)
   report['upstream_sha256']=hashlib.sha256(upstream.read_bytes()).hexdigest()
   report['upstream_build_info']=subprocess.check_output([a.go,'version','-m',str(upstream)],text=True).replace(str(upstream),'BUILD/nodepass-original')
   report['upstream_source_commit']=ORIGINAL
   report['upstream_built_from_archive']=not bool(a.upstream)
   if a.upstream:assert 'vcs.revision='+ORIGINAL in report['upstream_build_info'] and 'vcs.modified=false' in report['upstream_build_info'],'upstream binary provenance mismatch' 
   source=folder/'nodepass.gob';subprocess.run([str(helper),'write',str(source),'valid'],env=env,check=True,capture_output=True)
   original=source.read_bytes();digest=hashlib.sha256(original).hexdigest()
   expected=json.loads(subprocess.check_output([str(helper),'read',str(source)],env=env))
   def cli(args,success=True):
    done=subprocess.run([str(binary),'state',*args],env=dict(env,NP_RELOAD_INTERVAL='0s'),capture_output=True,text=True,timeout=5)
    assert (done.returncode==0)==success,'unexpected state CLI exit'
    assert KEY not in done.stdout+done.stderr and 'fixture-child' not in done.stdout+done.stderr,'state CLI disclosed credential'
    return json.loads(done.stdout) if success else None
   summary=cli(['inspect','--state',str(source)]);assert summary['instances']==2 and summary['sha256']==digest;passed('legacy-inspect')
   target=folder/'tunveo.gob';backup=folder/'source.backup';rollback=folder/'rollback.gob'
   cli(['migrate','--source',str(source),'--target',str(target),'--backup',str(backup)],False);assert not target.exists() and not backup.exists();passed('offline-ack-required')
   cli(['migrate','--offline','--source',str(source),'--target',str(target),'--backup',str(backup)])
   assert target.read_bytes()==backup.read_bytes()==source.read_bytes()==original;passed('migration-byte-identical',sha256=digest)
   assert target.stat().st_mode&0o777==0o600 and backup.stat().st_mode&0o777==0o600;passed('private-copy-permissions')
   decoded=json.loads(subprocess.check_output([str(helper),'read',str(target)],env=env));assert decoded==expected;passed('original-decoder-reads-migrated-state')
   for kind in ['no-key','invalid-id','invalid-url','quota','restart']:
    path=folder/(kind+'.gob');subprocess.run([str(helper),'write',str(path),kind],env=env,check=True,capture_output=True)
    if kind=='restart':assert cli(['inspect','--state',str(path)])['restart_enabled']==1;passed('inspect-restart-without-autostart')
    else:
     before=path.read_bytes();cli(['migrate','--offline','--source',str(path),'--target',str(folder/'rejected-target'),'--backup',str(folder/'rejected-backup')],False)
     assert path.read_bytes()==before and not (folder/'rejected-target').exists() and not (folder/'rejected-backup').exists();passed('reject/'+kind)
   for kind,data in [('truncated',original[:len(original)//2]),('trailing',original+b'bad')]:
    path=folder/(kind+'.gob');path.write_bytes(data);cli(['inspect','--state',str(path)],False);assert path.read_bytes()==data;passed('reject/'+kind)
   cli(['migrate','--offline','--source',str(source),'--target',str(target),'--backup',str(folder/'unused-backup')],False);assert target.read_bytes()==original and not (folder/'unused-backup').exists();passed('existing-target-untouched')
   cli(['restore','--offline','--source',str(backup),'--target',str(rollback)]);assert rollback.read_bytes()==original;passed('rollback-byte-identical')
   def oracle(executable,state,name,periodic=False):
    slot=folder/name;slot.mkdir();local=slot/executable.name;shutil.copy2(executable,local);(slot/'gob').mkdir();path=slot/'gob'/('nodepass.gob' if name.startswith('original') else 'tunveo.gob');path.write_bytes(state)
    port=free_port();runtime_env=dict(env,NP_RELOAD_INTERVAL='50ms') if periodic else env
    proc=subprocess.Popen([str(local),f'master://127.0.0.1:{port}?log=none'],env=runtime_env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    try:
     wait_ready(proc,port);conn=http.client.HTTPConnection('127.0.0.1',port,timeout=3);conn.request('GET','/api/v1/instances',headers={'X-API-Key':KEY});r=conn.getresponse();assert r.status==200;actual={entry['id']:entry for entry in json.loads(r.read())};conn.close();assert actual==expected,'runtime state fields differ'
     if periodic:
      deadline=time.monotonic()+3
      while not Path(str(path)+'.backup').exists():
       assert proc.poll() is None and time.monotonic()<deadline,'periodic backup deadline';time.sleep(.025)
    finally:logs=stop(proc)
    assert 'DATA RACE' not in logs and 'panic:' not in logs
    return path.read_bytes(),Path(str(path)+'.backup').read_bytes() if periodic else None
   current_saved,periodic_backup=oracle(binary,target.read_bytes(),'current',periodic=True);passed('current-runtime-load-and-save')
   current_path=folder/'current-saved.gob';current_path.write_bytes(current_saved);assert json.loads(subprocess.check_output([str(helper),'read',str(current_path)],env=env))==expected;passed('original-decoder-reads-current-save')
   oracle(upstream,current_saved,'original-after-current');passed('original-runtime-loads-current-save')
   oracle(upstream,rollback.read_bytes(),'original-rollback');passed('original-runtime-rolls-back-backup')

   periodic_path=folder/'periodic-backup.gob';periodic_path.write_bytes(periodic_backup)
   periodic_restore=folder/'periodic-restored.gob';cli(['restore','--offline','--source',str(periodic_path),'--target',str(periodic_restore)])
   assert periodic_restore.read_bytes()==periodic_backup;passed('periodic-backup-restore-exact')
   oracle(upstream,periodic_restore.read_bytes(),'original-periodic-restore');passed('original-runtime-restores-periodic-backup')
   large=folder/'oversized.gob'
   with large.open('wb') as stream:stream.truncate((128<<20)+1)
   cli(['inspect','--state',str(large)],False);passed('reject/oversized-before-decode')
   assert source.read_bytes()==backup.read_bytes()==rollback.read_bytes()==original;passed('source-backup-rollback-still-unchanged')
  report['status']='passed'
 except BaseException as e:report['status']='failed';report['error_type']=type(e).__name__;raise
 finally:
  a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'passed':len(rows)}))
if __name__=='__main__':main()
