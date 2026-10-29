import gzip,json,tempfile,unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]))
import soak_smaps_capture as c

class CaptureTests(unittest.TestCase):
    def run_capture(self,folder,values,guard=lambda:None,clock=None,validator=None):
        rows=iter(values)
        def validate(raw):
            if raw!='valid':raise ValueError('overlapping or unordered VMA')
        return c.capture(Path(folder),0,lambda:next(rows),guard,validator or validate,{'pid':1,'start_ticks':'2','key':['measured',5]},clock=clock)
    def test_rejected_original_and_valid_retry(self):
        with tempfile.TemporaryDirectory() as t:
            raw,start,end,wall=self.run_capture(t,['bad','valid'])
            self.assertEqual(raw,'valid');self.assertLessEqual(end-start,c.LIMIT_NS)
            p=Path(t)/'rejected-mappings/000.json';meta=json.loads(p.read_text())
            self.assertEqual(gzip.open(Path(t)/meta['attempts'][0]['file'],'rt').read(),'bad')
            self.assertEqual(meta['attempts'][0]['identity']['pid'],1)
    def test_second_invalid_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaisesRegex(ValueError,'two attempts'):self.run_capture(t,['bad','bad'])
            self.assertEqual(len(json.loads((Path(t)/'rejected-mappings/000.json').read_text())['attempts']),2)
    def test_budget_is_total_not_reset_between_attempts(self):
        now=[0]
        def clock():
            now[0]+=30_000_000
            return now[0]
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaisesRegex(ValueError,'100ms'):self.run_capture(t,['bad','valid'],clock=clock)
            self.assertTrue((Path(t)/'rejected-mappings/000.json').exists())
    def test_guard_failure_blocks_read_and_acceptance(self):
        def guard():raise ValueError('checkpoint changed')
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaisesRegex(ValueError,'checkpoint changed'):self.run_capture(t,[],guard)
            self.assertFalse((Path(t)/'snapshots.json').exists())
    def test_other_parse_errors_are_not_retried(self):
        calls=[]
        def invalid(raw):
            calls.append(raw)
            raise ValueError('incomplete VMA')
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaisesRegex(ValueError,'incomplete VMA'):self.run_capture(t,['bad','valid'],validator=invalid)
            self.assertEqual(calls,['bad'])
    def test_valid_first_read_needs_no_retry(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(self.run_capture(t,['valid'])[0],'valid')
            self.assertFalse((Path(t)/'rejected-mappings').exists())

if __name__=='__main__':unittest.main()
