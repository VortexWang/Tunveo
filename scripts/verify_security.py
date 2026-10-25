#!/usr/bin/env python3
"""Local process checks for TLS fail-closed startup and credential-safe logs.

Uses only synthetic credentials, loopback listeners, and temporary certificates.
Requires openssl and a built Tunveo binary. Deliberate api-key command output is
consumed in memory and never written to the report.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def cert_pair(folder, name):
    crt, key = folder / (name + '.crt'), folder / (name + '.key')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                    'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1',
                    '-keyout', str(key), '-out', str(crt)],
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    return crt, key


def request(port, path, key=None, context=None, method='GET', body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f'{"https" if context else "http"}://127.0.0.1:{port}/api/v1/{path}',
                                 data=data, method=method)
    if key:
        req.add_header('X-API-Key', key)
    if data:
        req.add_header('Content-Type', 'application/json')
    with urllib.request.urlopen(req, context=context, timeout=2) as r:
        return r.status, r.read()


def wait_ready(proc, port, context=None):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError('master exited before readiness')
        try:
            if request(port, 'openapi.json', context=context)[0] == 200:
                return
        except (OSError, urllib.error.URLError):
            time.sleep(.025)
    raise AssertionError('master readiness timed out')


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
    try:
        out, _ = proc.communicate(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise AssertionError('process required forced kill')
    assert proc.returncode == 0, f'process cleanup exit {proc.returncode}'
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    results = []
    binary = args.binary.resolve()
    report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'scope': 'local loopback; synthetic credentials; no production state', 'results': results}
    try:
        with tempfile.TemporaryDirectory(prefix='tunveo-security-') as temp:
            folder = Path(temp)
            local = folder / 'tunveo'
            shutil.copy2(binary, local)
            crt, key = cert_pair(folder, 'first')
            next_crt, next_key = cert_pair(folder, 'second')
            bad = folder / 'bad.pem'
            bad.write_text('invalid PEM')
            for role in ('server', 'client', 'master'):
                for name, options in (
                    ('missing-options', 'tls=2'),
                    ('missing-file', f'tls=2&crt={crt}.missing&key={key}'),
                    ('malformed-pem', f'tls=2&crt={bad}&key={key}'),
                    ('mismatched-key', f'tls=2&crt={crt}&key={next_key}'),
                    ('invalid-mode', 'tls=unexpected')):
                    port = free_port()
                    url = f'{role}://fixture-startup-secret@127.0.0.1:{port}/127.0.0.1:1?{options}&log=debug'
                    r = subprocess.run([str(local), url], stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, timeout=5)
                    assert r.returncode == 1, f'{role}/{name} did not fail closed'
                    assert 'TLS code-1' not in r.stdout and 'TLS code-0' not in r.stdout
                    assert 'fixture-startup-secret' not in r.stdout
                    with socket.socket() as sock:
                        sock.settimeout(.2)
                        assert sock.connect_ex(('127.0.0.1', port)) != 0
                    results.append({'case': f'{role}/{name}', 'status': 'passed', 'exit_code': 1})
            # Invalid URL errors must not echo even whitespace-containing userinfo.
            for raw in ('server://fixture-parse-secret@bad%zz/x',
                        'server://fixture space secret@127.0.0.1:1/x'):
                r = subprocess.run([str(local), raw], capture_output=True, text=True, timeout=5)
                assert r.returncode == 1
                assert 'fixture' not in r.stdout + r.stderr and 'space secret' not in r.stdout + r.stderr
            results.append({'case': 'malformed-url-errors', 'status': 'passed', 'inputs': 2})
            # Raw child output is inspected directly; the diagnostics runner's
            # masking is not involved in these assertions.
            for role in ('server', 'client'):
                port = free_port()
                url = f'{role}://fixture-raw-secret@127.0.0.1:{port}/127.0.0.1:1?mode=1&tls=0&log=debug'
                proc = subprocess.Popen([str(local), url], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                try:
                    time.sleep(.3)
                finally:
                    logs = stop(proc)
                assert f'{role.title()} started:' in logs
                assert 'fixture-raw-secret' not in logs and 'REDACTED' in logs
                results.append({'case': f'{role}/raw-startup-log', 'status': 'passed'})
            # Strict HTTPS, reload failure retaining the prior cert, then a
            # successful rotation to another valid cert and authenticated API use.
            port = free_port()
            env = dict(os.environ, NP_RELOAD_INTERVAL='50ms')
            url = f'master://127.0.0.1:{port}?tls=2&crt={crt}&key={key}&log=debug'
            proc = subprocess.Popen([str(local), url], env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            secrets = []
            try:
                context = ssl.create_default_context(cafile=str(crt))
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                wait_ready(proc, port, context)
                state = folder / 'gob/tunveo.gob'
                def read_key():
                    r = subprocess.run([str(local), 'api-key', '--state', str(state)],
                                       capture_output=True, text=True, check=True, timeout=3)
                    value = r.stdout.strip()
                    assert len(value) == 32 and not r.stderr
                    return value
                old_key = read_key()
                secrets.append(old_key)
                assert request(port, 'info', old_key, context)[0] == 200
                try:
                    request(port, 'info', context=context)
                    raise AssertionError('unauthenticated info accepted')
                except urllib.error.HTTPError as e:
                    assert e.code == 401
                key.write_text('invalid replacement')
                time.sleep(.075)
                assert request(port, 'info', old_key, context)[0] == 200
                crt.write_bytes(next_crt.read_bytes())
                key.write_bytes(next_key.read_bytes())
                time.sleep(.075)
                context = ssl.create_default_context(cafile=str(next_crt))
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                assert request(port, 'info', old_key, context)[0] == 200
                _, body = request(port, 'instances/********', old_key, context,
                                  method='PATCH', body={'action': 'restart'})
                new_key = json.loads(body)['url']
                secrets.append(new_key)
                assert new_key != old_key and request(port, 'info', new_key, context)[0] == 200
                deadline = time.monotonic() + 3
                while read_key() != new_key:
                    assert time.monotonic() < deadline
                    time.sleep(.025)
                try:
                    request(port, 'info', old_key, context)
                    raise AssertionError('old key accepted after rotation')
                except urllib.error.HTTPError as e:
                    assert e.code == 401
            finally:
                logs = stop(proc)
            assert all(secret not in logs for secret in secrets)
            assert 'retaining previous certificate' in logs and 'API Key regenerated;' in logs
            results.append({'case': 'master/strict-https-reload-and-key-rotation', 'status': 'passed',
                            'unauthenticated_status': 401, 'old_key_after_rotation_status': 401,
                            'raw_log_contains_key': False})
            # Restart reads the same persisted key but must not print it.
            port = free_port()
            proc = subprocess.Popen([str(local), f'master://127.0.0.1:{port}?log=debug'],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                wait_ready(proc, port)
                assert request(port, 'info', new_key)[0] == 200
            finally:
                logs = stop(proc)
            assert all(secret not in logs for secret in secrets) and 'API Key loaded;' in logs
            results.append({'case': 'master/restart-no-key-log', 'status': 'passed'})
        report['status'] = 'passed'
    except Exception as e:
        # Avoid exception bodies: HTTP/child responses can contain fixture keys.
        report['status'] = 'failed'
        report['failure_type'] = type(e).__name__
        raise
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'passed_cases': len(results)}))


if __name__ == '__main__':
    main()
