import copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from soak_cycles import fixed_envelope
import verify_soak as v
class FixedCycles(unittest.TestCase):
    def reports(self):
        rows=[]
        for i in range(1,4):
            def res(rss):return {'rss':rss,'goroutines':4,'fd':3,'heap_alloc':100}
            points=[{'at_seconds':t,'phase':'warmup','resources':res(100 if i==1 else 100+v.ACTIVE['rss'])} for t in [6,8,10]]+[{'at_seconds':t,'phase':'measured','resources':res(100 if i==1 else 101+v.ACTIVE['rss'])} for t in [12,17,22]]
            rows.append({'settings':{'pid':42,'warmup_seconds':12,'diagnostic_cycles':3,'diagnostic_cycle_index':i},'points':points,'idle_baseline':res(100),'after_stop':res(100),'post_stop_observation':[{'phase':'poststop_gc','resources':res(100),'at_seconds':t} for t in range(25)]+[{'phase':'poststop_go_scavenge','resources':res(100),'at_seconds':120}]})
        return rows
    def test_later_warmup_cannot_reset_fixed_envelope(self):
        r=self.reports();before=copy.deepcopy(r);x=fixed_envelope(r)
        self.assertEqual(x['baseline']['rss'],100);self.assertFalse(x['passed']);self.assertEqual(len(x['cycles'][1]['checks']['rss']['violations']),3)
        self.assertTrue(x['cycles'][1]['local_resources']['active']['rss']['passed']);self.assertEqual(r,before);self.assertFalse(x['qualifies_24h'])
    def test_pid_change_rejected(self):
        r=self.reports();r[1]['settings']['pid']=43
        with self.assertRaises(ValueError):fixed_envelope(r)
    def test_missing_round_rejected(self):
        with self.assertRaises(ValueError):fixed_envelope(self.reports()[:2])
    def test_missing_scavenge_rejected(self):
        r=self.reports();r[2]['post_stop_observation'].pop()
        with self.assertRaises(ValueError):fixed_envelope(r)
