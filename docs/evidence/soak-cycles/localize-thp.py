"""Localize PR33 AnonHugePages from immutable smaps; no runtime changes."""
import argparse,collections,gzip,hashlib,json,re,zipfile
from pathlib import Path
SHA='7320d208f1f2e42a95e252dc72733f15aa947370b27b3c5b511876264df2337a'
RANGES={'race_shadow':(0x200000000000,0x21c000000000),'race_metadata':(0x300000000000,0x400000000000)}
def parse(raw,race):
 rows=[];current=None
 for line in raw.splitlines():
  m=re.fullmatch(r'([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*(.*)',line)
  if m:
   current={'start':int(m[1],16),'end':int(m[2],16),'permissions':m[3],'name':m[7],'bytes':{}};assert current['start']<current['end'];rows.append(current)
  elif current:
   m=re.fullmatch(r'(Rss|AnonHugePages|Anonymous|LazyFree|KernelPageSize|MMUPageSize):\s+(\d+) kB',line)
   if m:assert m[1] not in current['bytes'];current['bytes'][m[1]]=int(m[2])*1024
   elif line.startswith('VmFlags:'):current['vm_flags']=line.split()[1:]
 for row in rows:
  name=row['name'];kind='other_named'
  if name=='[anon: Go: heap]':kind='go_named_heap'
  elif name.startswith('/') :kind='file'
  elif not name:kind='unnamed_anonymous'
  if race and not name:
   for label,(lo,hi) in RANGES.items():
    if lo<=row['start']<row['end']<=hi:kind=label
  row['category']=kind
  assert row['bytes'].get('AnonHugePages',0)<=row['bytes'].get('Rss',0)
 return rows

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert hashlib.sha256(a.archive.read_bytes()).hexdigest()==SHA
 out=[]
 with zipfile.ZipFile(a.archive) as z:
  assert z.testzip() is None
  for build in ['ordinary','race']:
   for cycle in range(1,4):
    root=f'{build}/cycle-{cycle}/';report=json.loads(z.read(root+'report.json'));records=[json.loads(x) for x in z.read(root+'mapping-index.jsonl').decode().splitlines()]
    n=len(report['post_stop_observation']);record=next(x for x in records if x['retention_points']==n and x['status']=='running')
    assert n==26 and record['pid']==report['settings']['pid'] and record['cycle']==cycle
    path=Path(record['file']);assert not path.is_absolute() and '..' not in path.parts
    raw=gzip.decompress(z.read(root+record['file']));assert hashlib.sha256(raw).hexdigest()==record['sha256_raw']
    rows=parse(raw.decode(),build=='race');groups={}
    for row in rows:
     g=groups.setdefault(row['category'],{'Rss':0,'AnonHugePages':0})
     for key in g:g[key]+=row['bytes'].get(key,0)
    point=report['post_stop_observation'][-1];assert point['phase']=='poststop_go_scavenge'
    out.append({'build':build,'cycle':cycle,'mapping_record':record,'resource_rss':point['resources']['rss'],'resource_rollup':point['resources']['os_memory']['bytes'],'snapshot_groups':groups,'huge_page_vmas':[r for r in rows if r['bytes'].get('AnonHugePages',0)],'snapshot_huge_bytes':sum(g['AnonHugePages'] for g in groups.values())})
 result={'archive_sha256':SHA,'rows':out,'scope':'First running checkpoint with complete 26 retention points, adjacent to Go-scavenge resource sample; smaps read is non-atomic. Fixed race address bands are address classification only. VMA names/bounds are not allocator callers, object identity or mapping generations. AnonHugePages is part of RSS, not additive.'}
 a.output.write_text(json.dumps(result,indent=2)+'\n')
 for r in out:print(r['build'],r['cycle'],{k:v['AnonHugePages']/1048576 for k,v in r['snapshot_groups'].items() if v['AnonHugePages']})
if __name__=='__main__':main()
