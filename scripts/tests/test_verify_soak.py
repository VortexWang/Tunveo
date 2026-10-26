import copy
import gzip
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('soak', Path(__file__).resolve().parents[1] / 'verify_soak.py')
soak = importlib.util.module_from_spec(spec)
spec.loader.exec_module(soak)


def fixture(duration=86400):
    metrics = dict(goroutines=4, fd=12, heap_alloc=1000000, rss=30000000)
    counts = dict(tcp=duration * 3 // 4 * 10, udp=duration // 4 * 10, failed=0, dropped=0)
    return dict(schema_version=1, status='passed', transport=0, mode=1, build_info='build\tvcs.modified=false\nbuild\tvcs.revision=' + 'a' * 40,
                settings=dict(tls=1, application_attempts=1, tcp_ratio=.75, udp_ratio=.25, observed_verifications=2,
                              observed_restarts=0, duration_seconds=duration, warmup_seconds=60, sample_interval_seconds=30, qps=10),
                measured_seconds=duration, stop_seconds=.01, counts=counts,
                warmup_counts=dict(tcp=450, udp=150, failed=0, dropped=0),
                points=[dict(at_seconds=n, phase='warmup', resources=metrics.copy(), counts=dict(tcp=0, udp=0, failed=0, dropped=0)) for n in range(0,60,5)] + [dict(at_seconds=n, phase='measured', resources=metrics.copy(), counts=counts.copy())
                        for n in range(60, duration + 61, 30)], idle_baseline=metrics.copy(), after_stop=metrics.copy())


class SoakEvidenceTests(unittest.TestCase):
    def test_full_and_pilot_admission_are_distinct(self):
        r = fixture()
        self.assertTrue(soak.validate_report(r, False)['qualifies_24h'])
        self.assertFalse(soak.validate_report(r, True)['qualifies_24h'])
        r = fixture(120)
        self.assertFalse(soak.validate_report(r, True)['qualifies_24h'])
        with self.assertRaises(ValueError):
            soak.validate_report(r, False)

    def test_partial_gaps_restarts_drops_and_source_mutation_rejected(self):
        mutations = [lambda r: r.update(measured_seconds=86399),
                     lambda r: r['settings'].update(observed_restarts=1),
                     lambda r: r['counts'].update(dropped=1),
                     lambda r: r['warmup_counts'].update(failed=1),
                     lambda r: r.update(build_info='-race=true vcs.modified=false vcs.revision=abc'),
                     lambda r: r.update(build_info='vcs.modified=true vcs.revision=abc'),
                     lambda r: r['points'].__delitem__(slice(10, 20)),
                     lambda r: r['points'].__delitem__(slice(100, None))]
        for mutate in mutations:
            r = fixture()
            mutate(r)
            with self.assertRaises(ValueError):
                soak.validate_report(r, False)

    def test_live_trend_and_return_leaks_rejected(self):
        for key, allowance in soak.TREND.items():
            r = fixture()
            for p in r['points'][len(r['points']) // 2:]:
                p['resources'][key] += allowance + 1
            with self.assertRaises(ValueError):
                soak.validate_report(r, False)
        for key, allowance in soak.RETURN.items():
            r = fixture()
            r['after_stop'][key] += allowance + 1
            with self.assertRaises(ValueError):
                soak.validate_report(r, False)

    def test_event_missing_duplicate_self_echo_and_digests_rejected(self):
        r = dict(settings=dict(workers=1, warmup_seconds=1, duration_seconds=10, front_port=22222, qps=10),
                 counts=dict(tcp=0, udp=0), warmup_counts=dict(tcp=1, udp=0))
        event = dict(sequence=0, worker=0, phase='warmup', scheduled_seconds=.1, protocol='tcp', bytes=32768,
                     sent_bytes=32768, received_bytes=32768, local='127.0.0.1:11111', peer='127.0.0.1:22222',
                     attempts=1, duration_seconds=.01, payload_sha256='a' * 64, reply_sha256='a' * 64)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'audit.gz'
            def save(rows):
                with gzip.open(path, 'wt') as f:
                    for row in rows:
                        f.write(json.dumps(row) + '\n')
            save([event])
            self.assertEqual(soak.validate_events(path, r), 1)
            for rows in ([], [event, event]):
                save(rows)
                with self.assertRaises(ValueError):
                    soak.validate_events(path, r)
            for change in ({'peer': event['local']}, {'attempts': 2}, {'received_bytes': 1}, {'reply_sha256': 'b' * 64}, {'sequence': 1}):
                row = copy.deepcopy(event)
                row.update(change)
                save([row])
                with self.assertRaises(ValueError):
                    soak.validate_events(path, r)

    def test_collector_refuses_empty_or_partial_suite(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from summarize_soak import collect
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                collect(Path(folder), True)

    def test_interrupt_reaps_native_process(self):
        import os
        import signal
        import subprocess
        import time
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            binary = root / 'fake-probe'
            binary.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(120)\n')
            binary.chmod(0o755)
            out = root / 'evidence'
            proc = subprocess.Popen(['python3', str(Path(soak.__file__)), '--binary', str(binary), '--transport', '0', '--mode', '1', '--pilot', '--duration-seconds', '60', '--artifacts', str(out)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 10
                child = None
                while time.monotonic() < deadline:
                    try:
                        child = json.loads((out / 'summary.json').read_text())['native_pid']
                        break
                    except (OSError, ValueError, KeyError):
                        time.sleep(.02)
                self.assertIsNotNone(child)
                proc.send_signal(signal.SIGTERM)
                proc.communicate(timeout=10)
                report = json.loads((out / 'summary.json').read_text())
                self.assertEqual(proc.returncode, 1)
                self.assertFalse(report['qualifies_24h'])
                self.assertEqual(report['cleanup'], dict(reaped=True, forced_kill=False, interrupted_or_timeout=True))
                with self.assertRaises(ProcessLookupError):
                    os.kill(child, 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate(timeout=5)


    def test_formal_build_preflight_rejects_race_or_unknown_source(self):
        valid='build\tvcs.modified=false\nbuild\tvcs.revision='+'a'*40
        soak.validate_build(valid)
        for info in ('', valid.replace('false','true'), valid+'\nbuild\t-race=true', 'vcs.revision=abc'):
            with self.assertRaises(ValueError):
                soak.validate_build(info)
