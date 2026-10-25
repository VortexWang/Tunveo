#!/usr/bin/env python3
"""Bounded loopback TCP/UDP diagnostics with persistent, per-phase evidence.

TLS mode 1 only. Success means this diagnostic passed, not a security audit.
Uses Python's standard library. Every application exchange is attempted once.
"""

import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid

ANSI = re.compile(r"\x1b\[[0-9;]*m")
CREDENTIAL = re.compile(r"((?:server|client)://)[^@\s]+@")
PAIRS = ("tunveo/tunveo", "upstream/upstream", "tunveo/upstream", "upstream/tunveo")
PHASES = ("server_startup", "tunnel_handshake", "pool_ready", "certificate_verification", "tcp_echo", "udp_echo", "cleanup")
FATAL = re.compile(r"(?:OutgoingVerify: (?:request timeout|no |certificate)|IncomingVerify: incomingGet failed|(?:Server|Client) (?:error|restart):|panic:|fatal error:)")


def clean(text):
    return CREDENTIAL.sub(r"\1[REDACTED]@", ANSI.sub("", text))


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as out:
        tmp = Path(out.name)
        try:
            json.dump(value, out, indent=2, ensure_ascii=False)
            out.write("\n")
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


class Reservation:
    """Reserve the same loopback port for TCP and UDP until process launch."""

    def __init__(self):
        for _ in range(100):
            self.tcp = socket.socket()
            self.udp = socket.socket(type=socket.SOCK_DGRAM)
            self.tcp.bind(("127.0.0.1", 0))
            self.port = self.tcp.getsockname()[1]
            try:
                self.udp.bind(("127.0.0.1", self.port))
                return
            except OSError:
                self.close()
        raise RuntimeError("no available loopback TCP/UDP port")

    def close(self):
        self.tcp.close()
        self.udp.close()


@contextlib.contextmanager
def echo_service():
    reservation = Reservation()
    tcp, udp = reservation.tcp, reservation.udp
    tcp.listen()
    tcp.settimeout(0.1)
    udp.settimeout(0.1)
    done = threading.Event()
    lock = threading.Lock()
    connections = set()
    workers = []

    def serve_conn(conn):
        try:
            with conn:
                conn.settimeout(0.1)
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
        finally:
            with lock:
                connections.discard(conn)

    def serve_tcp():
        while not done.is_set():
            try:
                conn, _ = tcp.accept()
                with lock:
                    connections.add(conn)
                thread = threading.Thread(target=serve_conn, args=(conn,), daemon=True)
                workers.append(thread)
                thread.start()
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

    listeners = [threading.Thread(target=f, daemon=True) for f in (serve_tcp, serve_udp)]
    for thread in listeners:
        thread.start()
    try:
        yield reservation.port
    finally:
        done.set()
        reservation.close()
        for thread in listeners:
            thread.join(timeout=1)
        with lock:
            for conn in connections:
                conn.close()
        for thread in workers:
            thread.join(timeout=1)


def exchange(port, udp=False, timeout=3):
    payload = bytes(range(256)) * (2 if udp else 128)
    deadline = time.monotonic() + timeout
    with socket.socket(type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as conn:
        def budget():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("total exchange deadline exceeded")
            conn.settimeout(remaining)
        budget()
        conn.connect(("127.0.0.1", port))
        budget()
        conn.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            budget()
            chunk = conn.recv(65536)
            if not chunk:
                raise RuntimeError("EOF before full echo")
            received.extend(chunk)
            if udp:
                break  # a truncated datagram must not be assembled from later packets
        if received != payload:
            raise RuntimeError(f"payload mismatch: sent={len(payload)} received={len(received)}")
    return {"sent_bytes": len(payload), "received_bytes": len(received), "attempts": 1}


def log_text(path):
    return clean(path.read_text(errors="replace")) if path.exists() else ""


def wait_logs(processes, paths, predicate, timeout):
    deadline = time.monotonic() + timeout
    while True:
        texts = [log_text(path) for path in paths]
        if any(p.poll() is not None for p in processes):
            raise RuntimeError("tunnel process exited before phase completion")
        for text in texts:
            match = FATAL.search(text)
            if match:
                line = text[match.start():].splitlines()[0]
                raise RuntimeError(f"engine failure before phase completion: {line}")
        if predicate(texts):
            return
        if time.monotonic() >= deadline:
            raise TimeoutError("phase log milestone not observed before deadline")
        time.sleep(min(0.025, max(0, deadline - time.monotonic())))


def stop_processes(processes, timeout):
    results = []
    for p in processes:
        if p.poll() is None:
            p.terminate()
    deadline = time.monotonic() + timeout
    for p in processes:
        forced = False
        try:
            p.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            forced = True
            p.kill()
            p.wait(timeout=2)
        results.append({"pid": p.pid, "returncode": p.returncode, "forced_kill": forced, "reaped": p.poll() is not None})
    return results


def run_case(server_bin, client_bin, row, folder, args, checkpoint):
    folder.mkdir()
    row.update(status="running", phases={name: {"status": "not_run"} for name in PHASES}, processes=[])
    processes, handles = [], []
    paths = [folder / "server.log", folder / "client.log"]
    row["logs"] = {"server": str(paths[0]), "client": str(paths[1])}
    reservations = []
    active_phase = None

    def phase(name, operation):
        nonlocal active_phase
        active_phase = name
        result = row["phases"][name]
        result.update(status="running", attempts=1)
        checkpoint()
        start = time.monotonic()
        try:
            details = operation()
            result.update(status="passed")
            if isinstance(details, dict):
                result.update(details)
        except BaseException as exc:
            result.update(status="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed", error=clean(str(exc)))
            raise
        finally:
            result["duration_seconds"] = round(time.monotonic() - start, 4)
            checkpoint()

    try:
        with echo_service() as target:
            front_res = Reservation()
            reservations.append(front_res)
            tunnel_res = Reservation()
            reservations.append(tunnel_res)
            front, tunnel = front_res.port, tunnel_res.port
            row["ports"] = {"echo": target, "front": front, "tunnel": tunnel}
            server_target, client_target = (front, target) if row["mode"] == 1 else (target, front)
            urls = [
                f"server://smoke-only@127.0.0.1:{tunnel}/127.0.0.1:{server_target}?mode={row['mode']}&type={row['transport']}&tls=1&max={row['pool']['max']}&log=debug",
                f"client://smoke-only@127.0.0.1:{tunnel}/127.0.0.1:{client_target}?mode=2&min={row['pool']['min']}&log=debug",
            ]
            row["commands"] = [[str(b), clean(u)] for b, u in zip((server_bin, client_bin), urls)]
            env = {k: v for k, v in os.environ.items() if not k.startswith(("NP_", "TUNVEO_"))}

            def launch(index, binary):
                if index == 0:
                    tunnel_res.close()
                if index == (0 if row["mode"] == 1 else 1):
                    front_res.close()
                handle = paths[index].open("w")
                handles.append(handle)
                p = subprocess.Popen([str(binary), urls[index]], stdout=handle, stderr=handle, cwd=folder, env=env)
                processes.append(p)
                row["processes"].append({"role": "server" if index == 0 else "client", "pid": p.pid})
                checkpoint()

            def startup():
                launch(0, server_bin)
                wait_logs(processes, paths[:1], lambda t: "Pending tunnel handshake" in t[0], args.startup_timeout)
            phase("server_startup", startup)
            def handshake():
                launch(1, client_bin)
                wait_logs(processes, paths, lambda t: "Sending tunnel config" in t[0] and "Loading tunnel config" in t[1], args.phase_timeout)
            phase("tunnel_handshake", handshake)
            phase("pool_ready", lambda: wait_logs(processes, paths, lambda t: all("Marking tunnel handshake as complete" in s for s in t), args.phase_timeout))
            # These are observed log milestones, not independent security proofs.
            phase("certificate_verification", lambda: wait_logs(processes, paths, lambda t: all("RAM cert verified with sha256 fingerprint" in s for s in t), args.phase_timeout))
            phase("tcp_echo", lambda: exchange(front, timeout=args.io_timeout))
            phase("udp_echo", lambda: exchange(front, udp=True, timeout=args.io_timeout))
        row["status"] = "passed"
    except KeyboardInterrupt:
        row.update(status="interrupted", failed_phase=active_phase)
        raise
    except Exception as exc:
        row.update(status="failed", failed_phase=active_phase, error=clean(str(exc)))
    finally:
        start = time.monotonic()
        try:
            stopped = stop_processes(processes, args.cleanup_timeout)
            row["cleanup"] = stopped
            forced = any(p["forced_kill"] for p in stopped)
            row["phases"]["cleanup"] = {"status": "failed" if forced else "passed", "forced_kill": forced}
            if forced and row["status"] == "passed":
                row.update(status="failed", failed_phase="cleanup", error="graceful cleanup deadline exceeded")
        except Exception as exc:
            row["phases"]["cleanup"] = {"status": "failed", "error": clean(str(exc))}
            if row["status"] != "interrupted":
                row.update(status="failed", failed_phase=row.get("failed_phase", "cleanup"), error=row.get("error", clean(str(exc))))
        finally:
            for handle in handles:
                handle.close()
            for reservation in reservations:
                reservation.close()
            for role, path in zip(("server", "client"), paths):
                raw = path.read_text(errors="replace") if path.exists() else ""
                row.setdefault("observations", {})[role] = {
                    "credential_url_observed": bool(CREDENTIAL.search(raw)),
                    "initiated_verification_ids": re.findall(r"verify signal: cid (\w+) ->", raw),
                    "received_verification_ids": re.findall(r"TLS verify signal: cid (\w+) <-", raw),
                    "verification_timeout": "OutgoingVerify: request timeout" in raw,
                    "restart_count": len(re.findall(r"(?:Server|Client) restart:", raw)),
                }
                path.write_text(clean(raw))
            row["phases"]["cleanup"]["duration_seconds"] = round(time.monotonic() - start, 4)
            checkpoint()


def binary_metadata(path, go):
    result = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    for name, command in (("version", [str(path), "version"]), ("go_build_info", [go, "version", "-m", str(path)])):
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=5)
            result[name] = clean(completed.stdout + completed.stderr).strip()
            result[name + "_exit_code"] = completed.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            result[name] = str(exc)
    return result


def parse_pair(text, limits=None):
    try:
        first, second = (int(s) for s in text.split(":"))
        if limits:
            assert first in limits[0] and second in limits[1]
        else:
            assert 0 < first <= second
        return first, second
    except (ValueError, AssertionError):
        raise argparse.ArgumentTypeError("expected transport:mode (0..3:1..2) or positive min:max")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--pair", choices=PAIRS, action="append", help="repeat to select pairings; defaults to all available")
    parser.add_argument("--case", type=lambda s: parse_pair(s, (range(4), (1, 2))), action="append", help="transport:server-mode; repeatable")
    parser.add_argument("--pool", type=parse_pair, action="append", help="min:max; repeatable; default 2:8")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--startup-timeout", type=float, default=5)
    parser.add_argument("--phase-timeout", type=float, default=15)
    parser.add_argument("--io-timeout", type=float, default=3)
    parser.add_argument("--cleanup-timeout", type=float, default=5)
    parser.add_argument("--artifacts", type=Path, help="new directory for logs and report")
    parser.add_argument("--output", type=Path, help="report path; defaults to ARTIFACTS/report.json")
    parser.add_argument("--go", default="go", help="Go executable for binary provenance")
    args = parser.parse_args(argv)
    if args.repeat < 1 or any(not 0 < v < float("inf") for v in (args.startup_timeout, args.phase_timeout, args.io_timeout, args.cleanup_timeout)):
        parser.error("repeat and timeouts must be positive and finite")
    pairs = list(dict.fromkeys(args.pair or (PAIRS if args.upstream else PAIRS[:1])))
    if not args.upstream and any(pair != PAIRS[0] for pair in pairs):
        parser.error("selected pairing requires --upstream")
    try:
        binaries = {"tunveo": args.binary.resolve(strict=True)}
        if args.upstream:
            binaries["upstream"] = args.upstream.resolve(strict=True)
    except OSError as exc:
        parser.error(str(exc))
    root = (args.artifacts or Path("artifacts/forwarding") / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])).resolve()
    root.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve() if args.output else root / "report.json"
    report = {"schema_version": 2, "status": "running", "started_at": datetime.now(timezone.utc).isoformat(), "environment": {"platform": platform.platform(), "machine": platform.machine(), "python": platform.python_version()}, "binaries": {k: binary_metadata(v, args.go) for k, v in binaries.items()}, "settings": {"tls": 1, "log_level": "debug", "application_attempts": 1, "readiness": "observed log milestones", "timeouts": {k: getattr(args, k) for k in ("startup_timeout", "phase_timeout", "io_timeout", "cleanup_timeout")}}, "results": []}
    def checkpoint():
        atomic_json(output, report)
    checkpoint()
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    old_term = signal.signal(signal.SIGTERM, interrupted)
    try:
        cases = list(dict.fromkeys(args.case or [(t, m) for m in (1, 2) for t in range(4)]))
        pools = list(dict.fromkeys(args.pool or [(2, 8)]))
        for pair, (transport, mode), (minimum, maximum), iteration in itertools.product(pairs, cases, pools, range(1, args.repeat + 1)):
            server, client = (binaries[k] for k in pair.split("/"))
            row = {"id": f"{len(report['results']) + 1:04d}", "pair_server_client": pair, "transport": transport, "mode": mode, "tls": 1, "pool": {"min": minimum, "max": maximum}, "iteration": iteration}
            report["results"].append(row)
            checkpoint()
            run_case(server, client, row, root / row["id"], args, checkpoint)
            print(json.dumps({k: row[k] for k in ("id", "pair_server_client", "transport", "mode", "pool", "iteration", "status", "failed_phase") if k in row}), flush=True)
        report["status"] = "failed" if any(row["status"] != "passed" for row in report["results"]) else "passed"
    except KeyboardInterrupt:
        report["status"] = "interrupted"
    except Exception as exc:
        report.update(status="runner_error", error=clean(str(exc)))
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        checkpoint()
        print(f"Evidence: {output}", flush=True)
        signal.signal(signal.SIGTERM, old_term)
    return {"passed": 0, "failed": 1, "runner_error": 2, "interrupted": 130}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
