#!/usr/bin/env python3
"""Build the immutable v1.17.0 oracle without editing its source or dependencies."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

ORIGINAL = '114345043d9608e1e24e783a270cde75193e4f42'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--go', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = a.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    archive = subprocess.check_output(['git', 'archive', ORIGINAL], cwd=root)
    with tempfile.TemporaryDirectory(prefix='tunveo-matrix-oracle-') as temp:
        folder = Path(temp)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(folder, filter='data')
        subprocess.run([a.go, 'build', '-trimpath', '-o', str(output), './cmd/nodepass'], cwd=folder, env=dict(os.environ, GOTOOLCHAIN='local'), check=True, timeout=240)
    provenance = {'source_commit': ORIGINAL, 'source_archive_sha256': hashlib.sha256(archive).hexdigest(), 'binary_sha256': hashlib.sha256(output.read_bytes()).hexdigest(), 'build_info': subprocess.check_output([a.go, 'version', '-m', str(output)], text=True), 'source_modified': False}
    output.with_suffix('.provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')
    print(json.dumps({'source_commit': ORIGINAL, 'binary_sha256': provenance['binary_sha256']}))


if __name__ == '__main__':
    main()
