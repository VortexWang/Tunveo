"""Bounded smaps retry; rejected bytes are evidence, never accepted snapshots."""
import gzip,hashlib,json,time
from pathlib import Path
LIMIT_NS=100_000_000

def capture(folder,number,read,guard,validate,identity,*,clock=None,wall=None):
    clock=clock or time.monotonic_ns
    wall=wall or time.time_ns
    started=clock();wall_started=wall();attempts=[]
    for attempt in range(2):
        guard()
        if clock()-started>LIMIT_NS:raise ValueError('smaps total capture exceeded 100ms')
        begin=clock();raw=read();end=clock()
        guard()
        try:
            validate(raw)
        except ValueError as error:
            relative=f'rejected-mappings/{number:03d}-{attempt:02d}.smaps.gz'
            target=Path(folder)/relative;target.parent.mkdir(parents=True,exist_ok=True)
            with gzip.open(target,'wt') as stream:stream.write(raw)
            attempts.append(dict(attempt=attempt,file=relative,sha256=hashlib.sha256(target.read_bytes()).hexdigest(),raw_sha256=hashlib.sha256(raw.encode()).hexdigest(),read_start_monotonic_ns=begin,read_end_monotonic_ns=end,error=str(error),identity=identity))
            index=Path(folder)/f'rejected-mappings/{number:03d}.json'
            temp=index.with_suffix('.tmp');temp.write_text(json.dumps(dict(total_start_monotonic_ns=started,attempts=attempts),indent=2)+'\n');temp.replace(index)
            if str(error)!='overlapping or unordered VMA':raise
            if attempt==1:raise ValueError('smaps invalid after two attempts') from error
            continue
        guard()
        finished=clock()
        if finished-started>LIMIT_NS:raise ValueError('smaps total capture exceeded 100ms')
        return raw,started,finished,wall_started
    raise AssertionError('unreachable')
