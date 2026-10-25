"""Black-box runner tests using controlled child processes and real sockets."""

import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_forwarding import exchange, ProbeSetupError
from probe_selfecho_fixture import ForcedSourceCollision

RUNNER = Path(__file__).resolve().parents[1] / 'verify_forwarding.py'
FIXTURE = '''#!/usr/bin/env python3
import os,socket,sys,threading,time
from urllib.parse import urlsplit,parse_qs
if sys.argv[1]=='version':
 print('fixture-dev');sys.exit(0)
u=urlsplit(sys.argv[1])
print('started '+sys.argv[1],flush=True)
print('Pending tunnel handshake',flush=True)
if u.scheme=='server':
 port=int(u.path.rsplit(':',1)[1]);tcp=socket.socket();tcp.bind(('127.0.0.1',port));tcp.listen()
 def worker():
  while True:
   c,_=tcp.accept()
   with c:
    while True:
     b=c.recv(65536)
     if not b:break
     c.sendall(b)
 threading.Thread(target=worker,daemon=True).start()
 udp=socket.socket(type=socket.SOCK_DGRAM);udp.bind(('127.0.0.1',port))
 def datagrams():
  while True:
   b,a=udp.recvfrom(65536)
   if os.environ.get('FIXTURE_MODE')!='drop-udp':udp.sendto(b,a)
 threading.Thread(target=datagrams,daemon=True).start()
tls=os.environ.get('FIXTURE_TLS',parse_qs(u.query).get('tls',['1'])[0])
if parse_qs(u.query).get('type',['0'])[0]=='1' and tls=='0':tls='1'
print('Sending tunnel config: TLS='+tls+'|',flush=True)
print('Loading tunnel config: TLS='+tls+'|',flush=True)
if os.environ.get('FIXTURE_MODE')!='no-pool':print('Marking tunnel handshake as complete',flush=True)
if os.environ.get('FIXTURE_MODE')!='no-verify':print('RAM cert verified with sha256 fingerprint: fixture',flush=True)
while True:time.sleep(.1)
'''


@unittest.skipUnless(os.name == 'posix', 'fixture uses executable scripts and POSIX signals')
class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.binary = self.root / 'fixture'
        self.binary.write_text(FIXTURE)
        self.binary.chmod(0o755)
        self.artifacts = self.root / 'evidence'

    def tearDown(self):
        self.tmp.cleanup()

    def command(self, *extra):
        return [sys.executable, str(RUNNER), '--binary', str(self.binary), '--case', '0:1', '--artifacts', str(self.artifacts), '--go', 'missing-go-tool-for-fixture', '--phase-timeout', '2', '--io-timeout', '.2', '--cleanup-timeout', '.5', *extra]

    def report(self):
        return json.loads((self.artifacts / 'report.json').read_text())

    def test_selected_cases_and_payloads(self):
        p = subprocess.run(self.command('--case', '2:1'), capture_output=True, text=True, timeout=8)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        rows = self.report()['results']
        self.assertEqual([r['transport'] for r in rows], [0, 2])
        for row in rows:
            self.assertEqual(row['phases']['tcp_echo']['received_bytes'], 32768)
            self.assertEqual(row['phases']['udp_echo']['received_bytes'], 512)
            self.assertTrue(all(p['reaped'] and not p['forced_kill'] for p in row['cleanup']))
            lengths = [len(Path(row['logs'][role]).read_bytes()) for role in ('server', 'client')]
            for phase in row['phases'].values():
                for index, observed in enumerate(phase.get('observed_log_bytes', [])):
                    self.assertLessEqual(observed, lengths[index])
            for role in ('server', 'client'):
                self.assertIn('RAM cert verified', Path(row['logs'][role]).read_text())

    def test_plain_mode_does_not_require_ram_fingerprint(self):
        env = dict(os.environ, FIXTURE_MODE='no-verify', FIXTURE_TLS='0')
        p = subprocess.run(self.command('--tls', '0'), env=env, capture_output=True, text=True, timeout=8)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        row = self.report()['results'][0]
        self.assertEqual(row['effective_tls'], 0)
        self.assertEqual(row['phases']['certificate_verification']['status'], 'not_applicable')
        self.assertEqual(row['phases']['tcp_echo']['status'], 'passed')

    def test_negative_control_rejects_a_ready_untrusted_pool(self):
        env = dict(os.environ, FIXTURE_TLS='2')
        p = subprocess.run(self.command('--tls', '2', '--reject-tls', 'untrusted-ca'), env=env, capture_output=True, text=True, timeout=8)
        self.assertEqual(p.returncode, 1, p.stderr + p.stdout)
        self.assertIn('untrusted data pool became ready', self.report()['results'][0]['error'])

    def test_negative_control_rejects_echo_even_without_ready_log(self):
        env = dict(os.environ, FIXTURE_TLS='2', FIXTURE_MODE='no-pool')
        p = subprocess.run(self.command('--tls', '2', '--reject-tls', 'untrusted-ca'), env=env, capture_output=True, text=True, timeout=8)
        self.assertEqual(p.returncode, 1, p.stderr + p.stdout)
        row = self.report()['results'][0]
        self.assertIn('unexpected application echo', row['error'])
        self.assertIn('local_endpoint', row['error'])
        self.assertEqual(row['failed_phase'], 'certificate_verification')

    def test_negotiated_mode_mismatch_is_a_failure(self):
        env = dict(os.environ, FIXTURE_TLS='0')
        p = subprocess.run(self.command(), env=env, capture_output=True, text=True, timeout=8)
        self.assertEqual(p.returncode, 1, p.stderr + p.stdout)
        self.assertEqual(self.report()['results'][0]['status'], 'failed')
        self.assertIn('negotiated TLS mode', self.report()['results'][0]['error'])

    def test_tcp_success_is_preserved_on_udp_timeout_and_logs_are_redacted(self):
        env = dict(os.environ, FIXTURE_MODE='drop-udp')
        p = subprocess.run(self.command(), env=env, capture_output=True, text=True, timeout=8)
        self.assertEqual(p.returncode, 1, p.stderr + p.stdout)
        row = self.report()['results'][0]
        self.assertEqual(row['failed_phase'], 'udp_echo')
        self.assertEqual(row['phases']['tcp_echo']['status'], 'passed')
        self.assertEqual(row['phases']['udp_echo']['attempts'], 1)
        self.assertTrue(row['observations']['server']['credential_url_observed'])
        all_logs = ''.join(p.read_text() for p in self.artifacts.glob('*/*.log'))
        self.assertNotIn('smoke-only@', all_logs)
        self.assertIn('[REDACTED]@', all_logs)

    def assert_interrupt_cleanup(self, stop_signal):
        env = dict(os.environ, FIXTURE_MODE='no-verify')
        p = subprocess.Popen(self.command('--phase-timeout', '20'), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if (self.artifacts / 'report.json').exists():
                    rows = self.report()['results']
                    if rows and rows[0].get('phases', {}).get('certificate_verification', {}).get('status') == 'running':
                        break
                time.sleep(.02)
            else:
                self.fail('runner did not persist in-progress phase')
            self.assertIn('Marking tunnel handshake', (self.artifacts / '0001/server.log').read_text())
            p.send_signal(stop_signal)
            out, err = p.communicate(timeout=5)
            self.assertEqual(p.returncode, 130, out + err)
            report = self.report()
            self.assertEqual(report['status'], 'interrupted')
            row = report['results'][0]
            self.assertEqual(row['phases']['pool_ready']['status'], 'passed')
            self.assertEqual(row['phases']['tcp_echo']['status'], 'not_run')
            self.assertTrue(all(child['reaped'] for child in row['cleanup']))
            for child in row['cleanup']:
                with self.assertRaises(ProcessLookupError):
                    os.kill(child['pid'], 0)
        finally:
            if p.poll() is None:
                p.kill()
                p.communicate(timeout=5)

    def test_interrupt_persists_partial_report_and_reaps_children(self):
        self.assert_interrupt_cleanup(signal.SIGINT)

    def test_terminate_persists_partial_report_and_reaps_children(self):
        self.assert_interrupt_cleanup(signal.SIGTERM)


class ExchangeTests(unittest.TestCase):
    def assert_self_connection_avoided(self, udp):
        fixture = ForcedSourceCollision(udp)
        with mock.patch('verify_forwarding.socket.socket', fixture.socket):
            with self.assertRaises(OSError):
                exchange(fixture.target[1], udp=udp, timeout=.2)
        self.assertGreaterEqual(len(fixture.sockets), 2)
        self.assertEqual(fixture.sockets[0].sends, 0)
        self.assertLessEqual(sum(s.sends for s in fixture.sockets), 1)
        self.assertTrue(all(s.closed for s in fixture.sockets))

    def test_tcp_source_cannot_be_the_destination(self):
        self.assert_self_connection_avoided(False)

    def test_udp_source_cannot_be_the_destination(self):
        self.assert_self_connection_avoided(True)

    def test_socket_allocation_failure_is_not_tls_rejection(self):
        with mock.patch('verify_forwarding.socket.socket', side_effect=OSError('fixture allocation failure')):
            with self.assertRaises(ProbeSetupError):
                exchange(1, udp=True, timeout=.2)

    def test_tcp_dribble_cannot_reset_total_deadline(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            done = threading.Event()
            def dribble():
                with listener.accept()[0] as conn:
                    conn.recv(65536)
                    while not done.is_set():
                        try:
                            conn.sendall(b'x')
                        except OSError:
                            return
                        done.wait(.03)
            thread = threading.Thread(target=dribble, daemon=True)
            thread.start()
            start = time.monotonic()
            try:
                with self.assertRaises(TimeoutError):
                    exchange(listener.getsockname()[1], timeout=.12)
                self.assertLess(time.monotonic() - start, .6)
            finally:
                done.set()
                thread.join(timeout=1)

    def test_short_udp_datagram_is_rejected(self):
        with socket.socket(type=socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            server.settimeout(1)
            def short():
                data, addr = server.recvfrom(65536)
                server.sendto(data[:10], addr)
            thread = threading.Thread(target=short, daemon=True)
            thread.start()
            with self.assertRaisesRegex(RuntimeError, 'payload mismatch'):
                exchange(server.getsockname()[1], udp=True, timeout=.3)
            thread.join(timeout=1)


if __name__ == '__main__':
    unittest.main()
