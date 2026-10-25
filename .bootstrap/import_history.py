import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('manifest', type=Path)
parser.add_argument('output', type=Path)
args = parser.parse_args()
data = json.loads(args.manifest.read_text())
assert data['upstream'] == 'https://github.com/NodePassProject/nodepass.git'
assert data['base'] == '114345043d9608e1e24e783a270cde75193e4f42'
assert data['expected_tip'] == '62bb7c84d4d5d3e739bd7819cb59f140360de7a3'
args.output.mkdir(parents=True, exist_ok=False)
def git(*argv, input=None):
    return subprocess.check_output(['git', '-C', str(args.output), *argv], input=input)
git('init', '-q')
git('fetch', '--no-tags', data['upstream'], data['base'])
git('checkout', '--detach', data['base'])
for commit in data['commits']:
    assert git('rev-parse', 'HEAD').decode().strip() == commit['parent']
    git('apply', '--index', '--whitespace=nowarn', '-', input=commit['patch'].encode())
    assert git('write-tree').decode().strip() == commit['tree']
    raw = commit['raw_commit'].encode()
    expected = hashlib.sha1(b'commit ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    assert expected == commit['sha']
    assert git('hash-object', '-t', 'commit', '-w', '--stdin', input=raw).decode().strip() == expected
    git('reset', '--hard', expected)
    print('Restored exact commit:', expected, flush=True)
assert git('rev-parse', 'HEAD').decode().strip() == data['expected_tip']
print('Verified full Tunveo history and source tree.')
