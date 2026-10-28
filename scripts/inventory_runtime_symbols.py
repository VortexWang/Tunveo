#!/usr/bin/env python3
"""Archive candidate code symbols and disassembly; no probes are attached."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
PATTERN=re.compile(r'TracePartAlloc|TracePartFree|TraceSwitchPart|InternalAlloc|InternalFree|MmapOrDie|UnmapOrDie|MmapFixed|ReleaseMemoryPagesToOS|DontNeedShadowFor|internal_mmap|internal_munmap')

def candidates(raw):
 out=[]
 for line in raw.splitlines():
  m=re.fullmatch(r'\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([TtWw])\s+(\S+)',line)
  if m and int(m[2],16)>0 and PATTERN.search(m[4]):out.append({'address':int(m[1],16),'size':int(m[2],16),'type':m[3],'symbol':m[4]})
 return out

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--artifacts',type=Path,required=True);a=p.parse_args();a.artifacts.mkdir(parents=True,exist_ok=False);binary=a.binary.resolve()
 raw=subprocess.check_output(['nm','-S','--defined-only',str(binary)],text=True);(a.artifacts/'nm.txt').write_text(raw)
 for name,command in [('program-headers.txt',['readelf','-W','-l',str(binary)]),('sections.txt',['readelf','-W','-S',str(binary)])]:(a.artifacts/name).write_text(subprocess.check_output(command,text=True))
 all_rows=candidates(raw);priority=['TracePartAlloc','TracePartFree','TraceSwitchPart','InternalAlloc','InternalFree','MmapOrDie','UnmapOrDie','ReleaseMemoryPagesToOS'];rows=sorted(all_rows,key=lambda r:(next((i for i,k in enumerate(priority) if k in r['symbol']),len(priority)),r['symbol']))[:128]
 for i,row in enumerate(rows):
  row['demangled']=subprocess.check_output(['c++filt',row['symbol']],text=True).strip();text=subprocess.check_output(['objdump','-d','--disassemble='+row['symbol'],str(binary)],text=True)
  file=f'candidate-{i:03d}.asm';(a.artifacts/file).write_text(text);row['disassembly_file']=file;row['return_instruction_lines']=[l for l in text.splitlines() if re.search(r'\bret[q]?\b',l)];row['qualification']='static candidate only; execution and uprobe safety unverified'
 result={'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'description':json.loads(subprocess.check_output([str(binary),'--describe'],timeout=10)),'candidate_count':len(all_rows),'bounded_to':128,'truncated':len(all_rows)>128,'candidates':rows,'qualifies_24h':False,'scope':'Missing standalone symbol can mean inline/elimination; a symbol/RET does not establish attachability, actual calls, object ownership or RSS attribution.'}
 (a.artifacts/'inventory.json').write_text(json.dumps(result,indent=2)+'\n')
if __name__=='__main__':main()
