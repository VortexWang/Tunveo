import copy
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('readiness',Path(__file__).resolve().parents[1]/'check_release_readiness.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class ReleaseReadinessTests(unittest.TestCase):
 def policy(self):return {'verified_input_sha256':'current','gates':[{'id':name,'status':'passed','evidence':['fixture']} for name in sorted(module.REQUIRED)]}
 def test_pending_gate_blocks(self):
  p=self.policy();p['gates'][0]['status']='pending';self.assertFalse(module.evaluate(p,'current')['release_ready'])
 def test_stale_fingerprint_blocks(self):self.assertIn('input_fingerprint',module.evaluate(self.policy(),'changed')['blockers'])
 def test_cannot_remove_gate(self):
  p=self.policy();p['gates'].pop()
  with self.assertRaises(ValueError):module.evaluate(p,'current')
 def test_pass_without_evidence_rejected(self):
  p=self.policy();p['gates'][0]['evidence']=[]
  with self.assertRaises(ValueError):module.evaluate(p,'current')
 def test_complete_matching_policy_passes(self):self.assertTrue(module.evaluate(self.policy(),'current')['release_ready'])
