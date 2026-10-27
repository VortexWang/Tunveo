import copy
import json
import sys
import unittest
import zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import soak_build_pair as pair

class ResourceDiagnostics(unittest.TestCase):
    def test_all_failures_and_boundaries(self):
        def point(t,phase,rss,fd):return {'at_seconds':t,'phase':phase,'resources':{'rss':rss,'fd':fd,'goroutines':4,'heap_alloc':10}}
        r={'settings':{'warmup_seconds':12},'points':[point(6,'warmup',100,2),point(8,'warmup',100,2),point(10,'warmup',100,2)]+[point(t,'measured',100+pair.v.ACTIVE['rss']+extra,20) for t,extra in [(12,0),(17,1),(22,2)]],'idle_baseline':{'goroutines':1,'fd':1,'heap_alloc':1},'after_stop':{'goroutines':20,'fd':20,'heap_alloc':1}}
        old=copy.deepcopy(r);d=pair.resources(r)
        self.assertEqual(len(d['active']['rss']['violations']),2)
        self.assertFalse(d['active']['fd']['passed']);self.assertFalse(d['return']['fd']['passed'])
        self.assertFalse(d['qualifies_24h']);self.assertFalse(d['trend']['rss']['enforced_in_pilot']);self.assertEqual(old,r)
    def test_insufficient_warmup_rejected(self):
        with self.assertRaises(ValueError):pair.resources({'settings':{'warmup_seconds':12},'points':[]})
