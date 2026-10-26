import copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]));import audit_soak_retention as r


class RetentionTests(unittest.TestCase):
 def fixture(self):
  return {'settings':{'post_stop_observe_seconds':5,'diagnostic_go_scavenge':True},
          'post_stop_observation':[{'phase':'poststop_gc','at_seconds':.01},
                                   {'phase':'poststop_gc','at_seconds':5.01},
                                   {'phase':'poststop_go_scavenge','at_seconds':5.03,'go_scavenge_seconds':.01}]}
 def test_forced_scavenge_must_follow_complete_gc_window(self):
  r.validate_retention_points(self.fixture())
  for mutate in (lambda x:x['post_stop_observation'].reverse(),
                 lambda x:x['post_stop_observation'].__delitem__(1),
                 lambda x:x['settings'].update(diagnostic_go_scavenge=False),
                 lambda x:x['post_stop_observation'][1].update(at_seconds=4),
                 lambda x:x['post_stop_observation'][2].update(go_scavenge_seconds=0)):
   x=self.fixture();mutate(x)
   with self.subTest(x=x),self.assertRaises(ValueError):r.validate_retention_points(x)


if __name__=='__main__':unittest.main()
