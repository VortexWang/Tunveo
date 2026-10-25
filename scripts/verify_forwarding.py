#!/usr/bin/env python3
"""Exercise real TCP/UDP forwarding, optionally against the upstream binary.

Uses loopback ports only. No third-party Python dependencies are required.
This is a smoke/interoperability check, not a security or stress test.
"""

import argparse
import contextlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


def free_port():
    # Ensure both protocols are available; processes bind after reservations close.
    for _ in range(100):
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            try:
                udp.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("could not find a free TCP/UDP port")


@contextlib.contextmanager
def echo_service():
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    port = tcp.getsockname()[1]
    tcp.listen()
    tcp.settimeout(0.2)
    udp = socket.socket(type=socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", port))
    udp.settimeout(0.2)
    done = threading.Event()

    def serve_conn(conn):
        with conn:
            conn.settimeout(0.2)
            while not done.is_set():
                try:
                    data = conn.recv(65536)
                    if not data:
                        return
                    conn.sendall(data)
                except socket.timeout:
                    continue
                except OSError:
                    return

    def serve_tcp():
        while not done.is_set():
            try:
                conn, _ = tcp.accept()
                threading.Thread(target=serve_conn, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                return

    def serve_udp():
        while not done.is_set():
            try:
                data, addr = udp.recvfrom(65536)
                udp.sendto(data, addr)
            except socket.timeout:
                continue
            except OSError:
                return

    workers = [threading.Thread(target=f, daemon=True) for f in (serve_tcp, serve_udp)]
    for worker in workers:
        worker.start()
    try:
        yield port
    finally:
        done.set()
        tcp.close()
        udp.close()
        for worker in workers:
            worker.join(timeout=1)


def exchange(port, udp=False):
    payload = os.urandom(512 if udp else 32768)
    with socket.socket(type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as conn:
        conn.settimeout(2)
        conn.connect(("127.0.0.1", port))
        conn.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            chunk = conn.recv(65536)
            if not chunk:
                raise RuntimeError("connection closed before full echo")
            received.extend(chunk)
        if received != payload:
            raise RuntimeError("forwarded payload differs")


def check(server_bin, client_bin, transport, mode):
    with echo_service() as target, tempfile.TemporaryDirectory(prefix="tunveo-smoke-") as tmp:
        front, tunnel = free_port(), free_port()
        while len({target, front, tunnel}) != 3:
            front, tunnel = free_port(), free_port()
        processes = []
        logs = []
        try:
            server_target, client_target = (front, target) if mode == 1 else (target, front)
            urls = [
                f"server://smoke-only@127.0.0.1:{tunnel}/127.0.0.1:{server_target}?mode={mode}&type={transport}&tls=1&max=8&log=info",
                f"client://smoke-only@127.0.0.1:{tunnel}/127.0.0.1:{client_target}?mode=2&min=2&max=8&log=info",
            ]
            # Use inherited defaults so the baseline comparison is not influenced
            # by the invoking shell's tuning variables.
            env = {k: v for k, v in os.environ.items() if not k.startswith(("NP_", "TUNVEO_"))}
            for i, (binary, url) in enumerate(zip((server_bin, client_bin), urls)):
                log = open(Path(tmp) / f"{i}.log", "w+")
                logs.append(log)
                processes.append(subprocess.Popen([str(binary), url], stdout=log, stderr=log, cwd=tmp, env=env))
                if i == 0:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        if "Pending tunnel handshake" in Path(log.name).read_text():
                            break
                        if processes[0].poll() is not None:
                            raise RuntimeError("server exited at startup")
                        time.sleep(0.05)
                    else:
                        raise RuntimeError("server did not reach handshake")
            for udp in (False, True):
                deadline = time.monotonic() + 15
                while True:
                    if any(p.poll() is not None for p in processes):
                        raise RuntimeError("tunnel process exited")
                    try:
                        exchange(front, udp)
                        break
                    except (OSError, RuntimeError):
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
            return {"transport": transport, "mode": mode, "tcp": "passed", "udp": "passed", "tls": 1}
        except Exception as exc:
            detail = "\n".join(Path(log.name).read_text()[-6000:] for log in logs)
            raise RuntimeError(f"{exc}\n{detail}") from exc
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            for log in logs:
                log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    pairs = [("tunveo/tunveo", binary, binary)]
    if args.upstream:
        upstream = args.upstream.resolve(strict=True)
        pairs += [("upstream/upstream", upstream, upstream), ("tunveo/upstream", binary, upstream), ("upstream/tunveo", upstream, binary)]
    results = []
    for pair, server, client in pairs:
        for mode in (1, 2):
            for transport in range(4):
                try:
                    result = check(server, client, transport, mode)
                    result["pair_server_client"] = pair
                except Exception as exc:
                    result = {"pair_server_client": pair, "transport": transport, "mode": mode, "error": str(exc)}
                results.append(result)
                print(json.dumps(result), flush=True)
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + "\n")
    return int(any("error" in r for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
