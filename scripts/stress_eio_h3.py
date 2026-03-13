#!/usr/bin/env python3

import argparse
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVER = ROOT / "_build/default/examples/eio/eio_h3_echo_server.exe"
CLIENT = ROOT / "_build/default/examples/eio/eio_h3_client.exe"


def ensure_file(path: pathlib.Path, size_mib: int) -> pathlib.Path:
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.truncate(size_mib * 1024 * 1024)
    return path


def wait_for_server(port: int, log: pathlib.Path, timeout_s: float = 5.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if log.exists() and "listening on UDP" in log.read_text(errors="replace"):
            return
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.sendto(b"", ("127.0.0.1", port))
            except OSError:
                pass
        time.sleep(0.05)
    raise RuntimeError(f"server on port {port} did not become ready:\n{log.read_text(errors='replace')}")


def run_client(args, stderr_path: pathlib.Path, timeout_s: float) -> str:
    with open(os.devnull, "wb") as stdout, open(stderr_path, "wb") as stderr:
        proc = subprocess.Popen(args, stdout=stdout, stderr=stderr, cwd=ROOT)
        try:
            rc = proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise RuntimeError(f"client timed out: {' '.join(args)}")
    if rc != 0:
        raise RuntimeError(
            f"client exited with {rc}: {' '.join(args)}\n{stderr_path.read_text(errors='replace')}"
        )
    return stderr_path.read_text(errors="replace")


def cancel_client(args, stderr_path: pathlib.Path, cancel_after_s: float, timeout_s: float) -> str:
    with open(os.devnull, "wb") as stdout, open(stderr_path, "wb") as stderr:
        proc = subprocess.Popen(args, stdout=stdout, stderr=stderr, cwd=ROOT)
        time.sleep(cancel_after_s)
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise RuntimeError(f"cancelled client did not exit: {' '.join(args)}")
    return stderr_path.read_text(errors="replace")


class ServerProcess:
    def __init__(self, port: int, args, workdir: pathlib.Path):
        self.port = port
        self.log = workdir / f"server-{port}.log"
        with open(os.devnull, "wb") as stdout, open(self.log, "wb") as stderr:
            self.proc = subprocess.Popen(args, stdout=stdout, stderr=stderr, cwd=ROOT)
        wait_for_server(port, self.log)

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def client_args(port: int, host: str, extra):
    return [str(CLIENT), "-p", str(port), *extra, host]


def run_download_phase(workdir: pathlib.Path, port: int, host: str, udp_connect: bool, iterations: int,
                       file_path: pathlib.Path, timeout_s: float, drop_recv_pct: float, drop_send_pct: float) -> None:
    extra_server = [str(SERVER), "-p", str(port), "-serve-file", str(file_path)]
    if drop_recv_pct:
        extra_server += ["-drop-recv-pct", str(drop_recv_pct)]
    if drop_send_pct:
        extra_server += ["-drop-send-pct", str(drop_send_pct)]
    server = ServerProcess(port, extra_server, workdir)
    try:
        client_extra = ["-download", "/dev/null"]
        if udp_connect:
            client_extra.insert(0, "-udp-connect")
        for i in range(iterations):
            run_client(
                client_args(port, host, client_extra),
                workdir / f"download-{host}-{'conn' if udp_connect else 'plain'}-{i}.log",
                timeout_s,
            )
    finally:
        server.stop()


def run_upload_phase(workdir: pathlib.Path, port: int, host: str, udp_connect: bool, iterations: int,
                     file_path: pathlib.Path, timeout_s: float, drop_recv_pct: float, drop_send_pct: float) -> None:
    extra_server = [str(SERVER), "-p", str(port), "-upload-out", "/dev/null"]
    if drop_recv_pct:
        extra_server += ["-drop-recv-pct", str(drop_recv_pct)]
    if drop_send_pct:
        extra_server += ["-drop-send-pct", str(drop_send_pct)]
    server = ServerProcess(port, extra_server, workdir)
    try:
        client_extra = ["-upload", str(file_path)]
        if udp_connect:
            client_extra.insert(0, "-udp-connect")
        for i in range(iterations):
            run_client(
                client_args(port, host, client_extra),
                workdir / f"upload-{host}-{'conn' if udp_connect else 'plain'}-{i}.log",
                timeout_s,
            )
    finally:
        server.stop()


def run_cancel_phase(workdir: pathlib.Path, port: int, host: str, udp_connect: bool, iterations: int,
                     file_path: pathlib.Path, timeout_s: float, cancel_after_s: float,
                     drop_recv_pct: float, drop_send_pct: float) -> None:
    extra_server = [str(SERVER), "-p", str(port), "-upload-out", "/dev/null"]
    if drop_recv_pct:
        extra_server += ["-drop-recv-pct", str(drop_recv_pct)]
    if drop_send_pct:
        extra_server += ["-drop-send-pct", str(drop_send_pct)]
    server = ServerProcess(port, extra_server, workdir)
    try:
        upload_extra = ["-upload", str(file_path)]
        probe_extra = ["-upload", str(file_path)]
        if udp_connect:
            upload_extra.insert(0, "-udp-connect")
            probe_extra.insert(0, "-udp-connect")
        for i in range(iterations):
            cancel_client(
                client_args(port, host, upload_extra),
                workdir / f"cancel-{host}-{'conn' if udp_connect else 'plain'}-{i}.log",
                cancel_after_s,
                timeout_s,
            )
            run_client(
                client_args(port, host, probe_extra),
                workdir / f"cancel-followup-{host}-{'conn' if udp_connect else 'plain'}-{i}.log",
                timeout_s,
            )
    finally:
        server.stop()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--cancel-after", type=float, default=0.5)
    parser.add_argument("--drop-recv-pct", type=float, default=0.0)
    parser.add_argument("--drop-send-pct", type=float, default=0.0)
    parser.add_argument("--payload", type=pathlib.Path, default=None)
    parser.add_argument("--payload-mib", type=int, default=128)
    parser.add_argument("--cancel-payload-mib", type=int, default=512)
    parser.add_argument("--workdir", type=pathlib.Path, default=None)
    args = parser.parse_args()

    workdir = args.workdir or pathlib.Path(tempfile.mkdtemp(prefix="oq-stress-"))
    workdir.mkdir(parents=True, exist_ok=True)

    payload = args.payload
    if payload is None:
        payload = ensure_file(workdir / f"payload-{args.payload_mib}mib.bin", args.payload_mib)
    cancel_payload = ensure_file(workdir / f"cancel-payload-{args.cancel_payload_mib}mib.bin", args.cancel_payload_mib)

    scenarios = [
        ("download", run_download_phase, "127.0.0.1", False, payload, 5600),
        ("download", run_download_phase, "127.0.0.1", True, payload, 5601),
        ("download", run_download_phase, "localhost", True, payload, 5602),
        ("upload", run_upload_phase, "127.0.0.1", False, payload, 5603),
        ("upload", run_upload_phase, "127.0.0.1", True, payload, 5604),
        ("upload", run_upload_phase, "localhost", True, payload, 5605),
        ("cancel", run_cancel_phase, "127.0.0.1", False, cancel_payload, 5606),
        ("cancel", run_cancel_phase, "127.0.0.1", True, cancel_payload, 5607),
        ("cancel", run_cancel_phase, "localhost", True, cancel_payload, 5608),
    ]

    try:
        for name, fn, host, udp_connect, file_path, port in scenarios:
            print(
                f"[stress] {name} host={host} udp_connect={udp_connect} "
                f"iters={args.iterations} port={port}",
                flush=True,
            )
            if name == "cancel":
                fn(
                    workdir,
                    port,
                    host,
                    udp_connect,
                    args.iterations,
                    file_path,
                    args.timeout,
                    args.cancel_after,
                    args.drop_recv_pct,
                    args.drop_send_pct,
                )
            else:
                fn(
                    workdir,
                    port,
                    host,
                    udp_connect,
                    args.iterations,
                    file_path,
                    args.timeout,
                    args.drop_recv_pct,
                    args.drop_send_pct,
                )
    except Exception as exn:
        print(f"[stress] failure: {exn}", file=sys.stderr)
        print(f"[stress] logs: {workdir}", file=sys.stderr)
        return 1

    print(f"[stress] ok logs={workdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
