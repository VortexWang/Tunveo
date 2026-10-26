"""Loaded only inside GDB. Function-entry/return observations, not a syscall ledger."""
import gdb
import json
import os
from pathlib import Path
import shlex
import time

folder=Path(os.environ['TUNVEO_GDB_OUTPUT']).resolve()
config=json.loads((folder/'gdb-config.json').read_text())
stream=(folder/'mmap-calls.jsonl').open('w')
state={'entry_calls':0,'returns':0,'finish_errors':[], 'out_of_scope':[], 'exit_code':None,
       'gdb_version':gdb.VERSION,'scope':'entry/return breakpoint observations only; no complete mmap/unmap ledger, no RSS attribution'}


def emit(record):
    record['at_unix_ns']=time.time_ns()
    record['inferior_pid']=gdb.selected_inferior().pid
    record['thread_ptid']=list(gdb.selected_thread().ptid)
    stream.write(json.dumps(record)+'\n');stream.flush()


class Returned(gdb.FinishBreakpoint):
    def __init__(self,frame,call_id):
        super().__init__(frame, internal=True)
        self.call_id=call_id
    def stop(self):
        emit({'event':'return','id':self.call_id,'rax':int(gdb.parse_and_eval('$rax')) & ((1<<64)-1)})
        state['returns']+=1
        return False
    def out_of_scope(self):
        state['out_of_scope'].append(self.call_id)


class Entered(gdb.Breakpoint):
    def stop(self):
        state['entry_calls']+=1;call_id=state['entry_calls']
        args={name:int(gdb.parse_and_eval('$'+name)) & ((1<<64)-1)
              for name in ('rdi','rsi','rdx','rcx','r8','r9','rsp','rip')}
        # C ABI registers are captured at the EXACT function entry address.
        # Preserve GDB's own unwind output, including failure/unknown frames.
        emit({'event':'entry','id':call_id,'registers':args,
              'backtrace':gdb.execute('bt 32',to_string=True)})
        try:Returned(gdb.newest_frame(),call_id)
        except (gdb.error,ValueError) as error:
            state['finish_errors'].append({'id':call_id,'error':str(error)})
        return False


def exited(event):
    state['exit_code']=getattr(event,'exit_code',None)


gdb.execute('set pagination off');gdb.execute('set confirm off')
gdb.execute('set disable-randomization off')
gdb.execute('handle SIGURG nostop noprint pass')
gdb.execute('handle SIGPIPE nostop noprint pass')
gdb.events.exited.connect(exited)
# nm records the symbol and exact address before GDB starts. No inferred offset.
Entered('*0x'+format(config['entry_address'],'x'),internal=True)
try:
    gdb.execute(config['run_command'])
finally:
    stream.close()
    (folder/'gdb-result.json').write_text(json.dumps(state,indent=2)+'\n')
if state['exit_code'] != 0:
    gdb.execute('quit 1')
