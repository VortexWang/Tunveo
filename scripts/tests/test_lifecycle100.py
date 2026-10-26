"""Evidence-oracle tests: incomplete or leaking runs must never turn green."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('lifecycle', Path(__file__).resolve().parents[1] / 'verify_lifecycle100.py')
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)


def fixture():
    metrics = dict(cycle=0, goroutines=4, fd=12, heap_alloc=500000, heap_inuse=1000000, sys=8000000, rss=20000000)
    exchange = [dict(protocol='tcp', local='127.0.0.1:30001', peer='127.0.0.1:30002', bytes=32768, attempts=1),
                dict(protocol='udp', local='127.0.0.1:30003', peer='127.0.0.1:30002', bytes=512, attempts=1)]
    scenarios = []
    for kind in lifecycle.KINDS:
        for mode in (1, 2):
            rows = [dict(number=n, stop_seconds=.01, duration_seconds=.5, exchanges=copy.deepcopy(exchange)) for n in range(1, 101)]
            scenarios.append(dict(kind=kind, mode=mode, warmup=5, baseline=metrics.copy(), final=dict(metrics, cycle=100),
                                  samples=[dict(metrics, cycle=n) for n in range(10, 101, 10)], cycles=rows))
    return dict(schema_version=1, status='passed', transport=0, requested_cycles_per_scenario=100, scenarios=scenarios)


class LifecycleEvidenceTests(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(lifecycle.validate(fixture(), 100)['cycles'], 400)

    def test_failed_and_partial_runs_rejected(self):
        for mutate in (lambda r: r.update(status='failed'),
                       lambda r: r['scenarios'].pop(),
                       lambda r: r['scenarios'][0]['cycles'].pop(),
                       lambda r: r['scenarios'][0]['samples'].pop(),
                       lambda r: r['scenarios'][0]['cycles'][0].update(error='timeout'),
                       lambda r: r['scenarios'][0]['cycles'][0].update(stop_seconds=5)):
            r = fixture()
            mutate(r)
            with self.assertRaises(AssertionError):
                lifecycle.validate(r, 100)

    def test_resource_leaks_and_missing_metrics_rejected(self):
        for metric, allowance in lifecycle.LIMITS.items():
            r = fixture()
            s = r['scenarios'][0]
            s['final'][metric] = s['baseline'][metric] + allowance + 1
            with self.assertRaises(AssertionError):
                lifecycle.validate(r, 100)
        r = fixture()
        del r['scenarios'][0]['final']['rss']
        with self.assertRaises(KeyError):
            lifecycle.validate(r, 100)

    def test_self_echo_and_application_retry_rejected(self):
        for change in ({'peer': '127.0.0.1:30001'}, {'attempts': 2}, {'bytes': 1}):
            r = fixture()
            r['scenarios'][0]['cycles'][0]['exchanges'][0].update(change)
            with self.assertRaises(AssertionError):
                lifecycle.validate(r, 100)


if __name__ == '__main__':
    unittest.main()
