#!/usr/bin/env python3
"""Run uninstrumented native management boundary regressions against a git archive."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ref', required=True)
    parser.add_argument('--mode', choices=['original', 'fixed'], required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--repeat', type=int, default=10)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(['git', 'rev-parse', args.ref], cwd=root, text=True).strip()
    template = (root / 'internal/master/management_boundary_test.go').read_bytes()
    archive = subprocess.check_output(['git', 'archive', commit], cwd=root)
    with tempfile.TemporaryDirectory(prefix='tunveo-management-') as temp:
        folder = Path(temp)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(folder, filter='data')
        test = template.decode().replace('var expectManagementFailure = false', 'var expectManagementFailure = ' + ('true' if args.mode == 'original' else 'false'))
        (folder / 'internal/master/management_boundary_test.go').write_text(test)
        if args.mode == 'original':
            source = (folder / 'internal/master/master.go').read_text()
            registration = source[source.index('\tmux := http.NewServeMux()'):source.index('\tm.Server = &http.Server{')]
            helper = 'package master\nimport("context";"fmt";"net/http";"strings")\nfunc fixtureManagementHandler(m *Master)http.Handler{\n' + registration + '\nreturn mux\n}\nfunc fixtureManagementPing(m *Master,_ context.Context,target string)*TCPingResult{return m.PerformTCPing(target)}\n'
        else:
            helper = (root / 'internal/master/management_fixture_test.go').read_text()
        (folder / 'internal/master/management_fixture_test.go').write_text(helper)
        run = subprocess.run([args.go, 'test', '-race', '-run', '^TestManagement(MissingKeyFailsClosed|BodyLimit|TrailingJSONRejected|SSEOmitsAPIKey|CanceledPingStopsWaiting)$',
                              '-count', str(args.repeat), '-v', './internal/master'], cwd=folder,
                             env=dict(os.environ, GOTOOLCHAIN='local'), capture_output=True, text=True, timeout=120)
    marker = 'REPRODUCED-' if args.mode == 'original' else 'PASSED-'
    counts = {name.lower(): run.stdout.count(marker + name + ':') for name in ['AUTH','BODY','TRAILING','SSEKEY','CANCEL']}
    result = {'source_commit': commit, 'mode': args.mode, 'scope': 'native production handlers; synthetic key; bounded in-memory HTTP and canceled ping; original route registration copied verbatim from Run into test adapter',
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'template_sha256': hashlib.sha256(template).hexdigest(),
              'route_adapter_sha256': hashlib.sha256(helper.encode()).hexdigest(), 'repeat_per_scenario': args.repeat,
              'scenarios': counts, 'test_exit_code': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}
    result['status'] = ('reproduced' if args.mode == 'original' else 'passed') if run.returncode == 0 and all(n == args.repeat * (2 if name in ('auth','body') else 1) for name,n in counts.items()) else 'failed'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ['source_commit', 'mode', 'status', 'scenarios']}))
    if result['status'] == 'failed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
