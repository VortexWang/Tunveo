import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from summarize_soak import collect


def save_summary(folder, **changes):
    path = folder / 'summary.json'
    summary = json.loads(path.read_text())
    summary.update(changes)
    summary['files'] = {str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in folder.rglob('*') if p.is_file() and p.name != 'summary.json'}
    path.write_text(json.dumps(summary))


def make_suite(root):
    for transport in range(4):
        for mode in (1, 2):
            folder = root / f'{transport}-{mode}'
            native = folder / 'native'
            native.mkdir(parents=True)
            metrics = dict(goroutines=4, fd=12, heap_alloc=1000000, rss=30000000)
            counts = dict(tcp=3, udp=1, failed=0, dropped=0)
            settings = dict(tls=1, application_attempts=1, tcp_ratio=.75, udp_ratio=.25,
                            observed_verifications=2, observed_restarts=0, duration_seconds=4,
                            warmup_seconds=12, sample_interval_seconds=1, qps=1, workers=1,
                            pool_min=16, pool_max=64, front_port=22222)
            points = [dict(at_seconds=n, phase='warmup', resources=metrics, counts=dict(tcp=0, udp=0, failed=0, dropped=0))
                      for n in range(0, 12, 2)]
            points += [dict(at_seconds=n, phase='measured', resources=metrics, counts=counts) for n in range(12, 17)]
            report = dict(schema_version=1, status='passed', transport=transport, mode=mode,
                          build_info='build\tvcs.modified=false\nbuild\tvcs.revision=' + 'a' * 40,
                          settings=settings, measured_seconds=4, stop_seconds=.01, counts=counts,
                          warmup_counts=dict(tcp=9, udp=2, failed=0, dropped=0), points=points,
                          idle_baseline=metrics, after_stop=metrics)
            (native / 'report.json').write_text(json.dumps(report))
            with gzip.open(native / 'exchanges.jsonl.gz', 'wt') as f:
                for seq in range(15):
                    proto = 'udp' if seq % 4 == 3 else 'tcp'
                    size = 512 if proto == 'udp' else 32768
                    row = dict(sequence=seq, worker=0, phase='warmup' if seq+1 < 12 else 'measured',
                               scheduled_seconds=seq+1, protocol=proto, bytes=size, sent_bytes=size,
                               received_bytes=size, local='127.0.0.1:11111', peer='127.0.0.1:22222',
                               attempts=1, duration_seconds=.01, payload_sha256=f'{seq:064x}', reply_sha256=f'{seq:064x}')
                    f.write(json.dumps(row) + '\n')
            with gzip.open(native / 'engine.log.gz', 'wt') as f:
                f.write('RAM cert verified with sha256 fingerprint\n' * 2)
                f.write(f'Sending tunnel config: MAX=64|TLS=1|TYPE={transport}|\n')
                f.write(f'Loading tunnel config: MAX=64|TLS=1|TYPE={transport}|\n')
            (folder / 'stdout.log').write_text('')
            (folder / 'stderr.log').write_text('')
            (folder / 'summary.json').write_text(json.dumps(dict(pilot=True, status='pilot_passed', qualifies_24h=False,
                exit_code=0, binary_sha256='b' * 64, runner_sha256='c' * 64, cleanup=dict(reaped=True, forced_kill=False))))
            save_summary(folder)


class SuiteRawLogTests(unittest.TestCase):
    def test_complete_short_suite_revalidated_without_24h_promotion(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_suite(root)
            result = collect(root, True)
            self.assertEqual(len(result['profiles']), 8)
            self.assertFalse(result['qualifies_24h'])

    def test_semantically_invalid_logs_rejected_even_with_matching_hashes(self):
        for mutation in ('panic', 'restart', 'missing-verification', 'extra-verification', 'wrong-pool', 'wrong-tls', 'wrong-type', 'stderr-race'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                make_suite(root)
                folder = root / '0-1'
                path = folder / 'native/engine.log.gz'
                with gzip.open(path, 'rt') as f:
                    text = f.read()
                if mutation == 'panic':
                    text += 'panic: controlled invalid evidence\n'
                elif mutation == 'restart':
                    text += 'Client restart\n'
                elif mutation == 'missing-verification':
                    text = text.replace('RAM cert verified with sha256 fingerprint\n', '', 1)
                elif mutation == 'extra-verification':
                    text += 'RAM cert verified with sha256 fingerprint\n'
                elif mutation == 'wrong-pool':
                    text = text.replace('MAX=64', 'MAX=65')
                elif mutation == 'wrong-tls':
                    text = text.replace('TLS=1', 'TLS=2')
                elif mutation == 'wrong-type':
                    text = text.replace('TYPE=0', 'TYPE=1')
                else:
                    (folder / 'stderr.log').write_text('WARNING: DATA RACE\n')
                with gzip.open(path, 'wt') as f:
                    f.write(text)
                # The inventory is consistent. Acceptance must inspect meaning.
                save_summary(folder)
                with self.assertRaises(ValueError):
                    collect(root, True)

    def test_nonzero_and_interrupted_summaries_cannot_claim_success(self):
        for change in (dict(exit_code=1), dict(error='interrupted'),
                       dict(cleanup=dict(reaped=True, forced_kill=False, interrupted_or_timeout=True))):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                make_suite(root)
                save_summary(root / '0-1', **change)
                with self.assertRaises(ValueError):
                    collect(root, True)
