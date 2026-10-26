import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]));import audit_soak_allocations as a

class AllocationTests(unittest.TestCase):
 def test_trace_threads_replacement_and_unfinished(self):
  raw='''1 1.000000 clone(child_stack=NULL, flags=CLONE_THREAD) = 2 <0.000001>
2 1.100000 mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 <unfinished ...>
9 1.100000 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, -1, 0) = 0x9000 <0.000001>
 > lib(__tsan::TracePartAlloc+0x1) [0x1]
2 1.100001 <... mmap resumed>) = 0x1000 <0.000010>
 > lib(__tsan::TracePartAlloc+0x1) [0x1]
2 1.200000 munmap(0x2000, 4096) = 0 <0.000001>
'''
  events=a.native_events(a.parse_trace(raw),1)
  self.assertEqual(len(events),3)
  intervals=a.allocations_at(events,a.ns('1.3'))
  self.assertEqual(intervals,[(4096,8192,'race_trace')])
  self.assertEqual(a.owner_of(dict(start=4096,end=8192),intervals),'race_trace')
  self.assertEqual(a.owner_of(dict(start=4096,end=12288),intervals),'unresolved')
 def test_failed_map_and_remap_do_not_invent_ownership(self):
  raw="""1 1.0 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, -1, 0) = -1 ENOMEM (Cannot allocate memory) <0.000001>
1 2.0 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, -1, 0) = 0x1000 <0.000001>
 > lib(__tsan::InternalAlloc+0x1) [0x1]
1 3.0 mremap(0x1000, 4096, 8192, MREMAP_MAYMOVE) = 0x4000 <0.000001>
"""
  e=a.parse_trace(raw)
  self.assertEqual(a.allocations_at(e,a.ns('1.5')),[])
  self.assertEqual(a.allocations_at(e,a.ns('2.5')),[(4096,8192,'race_allocator_other')])
  self.assertEqual(a.allocations_at(e,a.ns('3.5')),[(16384,24576,'unresolved')])
 def test_real_strace_resumed_argument_whitespace(self):
  raw="""1 1.0 mmap(NULL, 8192 , PROT_READ, MAP_PRIVATE, -1, 0) = 0x1000 <0.000001>
 > lib(__tsan::InternalAlloc+0x1) [0x1]
1 2.0 munmap(0x1000, 8192 <unfinished ...>
1 2.000001 <... munmap resumed>) = 0 <0.000010>
"""
  events=a.parse_trace(raw)
  self.assertEqual(a.allocations_at(events,a.ns('1.5')),[(4096,12288,'race_allocator_other')])
  self.assertEqual(a.allocations_at(events,a.ns('2.5')),[])
 def test_no_rss_prorating_or_guessed_allocator(self):
  v=dict(start=0,end=4096)
  self.assertEqual(a.owner_of(v,[(0,2048,'race_trace'),(2048,4096,'race_allocator_other')]),'race_runtime_mixed')
  self.assertEqual(a.owner_of(v,[(0,2048,'race_trace'),(2048,4096,'unresolved')]),'unresolved')
  self.assertEqual(a.stack_owner(['libc(mmap+0x1)']),'unresolved')
  with self.assertRaises(ValueError):a.parse_trace('1 1.0 mmap(NULL, 4096 <unfinished ...>\n')

if __name__=='__main__':unittest.main()
