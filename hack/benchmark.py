#!/usr/bin/env python3
"""Compare only Trojan/gRPC/TLS download throughput via two local cores."""

import argparse
import contextlib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, unquote, urlsplit


class BenchmarkError(Exception):
    pass


def parse_server(uri):
    try:
        url = urlsplit(uri)
        query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
        allowed = {"security", "type", "sni", "alpn", "authority", "serviceName", "fp"}
        if (url.scheme != "trojan" or not url.hostname or not url.port
                or not url.username or url.password is not None or url.path not in ("", "/")
                or set(query) - allowed or any(len(v) != 1 for v in query.values())
                or query.get("security") != ["tls"] or query.get("type") != ["grpc"]):
            raise ValueError()
        value = {k: v[0] for k, v in query.items()}
        if (any(not v or any(ord(c) < 32 for c in v) for v in value.values())
                or not value.get("serviceName") or "/" in value["serviceName"]
                or any(not item for item in value.get("alpn", "h2").split(","))
                or "h2" not in value.get("alpn", "h2").split(",")):
            raise ValueError()
        return {
            "address": url.hostname, "port": url.port, "password": unquote(url.username),
            "sni": value.get("sni", url.hostname),
            "alpn": value.get("alpn", "h2").split(","),
            "authority": value.get("authority", value.get("sni", url.hostname)),
            "service": value.get("serviceName", ""), "fingerprint": value.get("fp"),
        }
    except (ValueError, TypeError, AttributeError):
        raise BenchmarkError("server must be a supported trojan:// URI with type=grpc and security=tls") from None


def executable(value, base):
    if not isinstance(value, str) or not value:
        raise BenchmarkError("binary paths must be non-empty strings")
    path = str((base / value).resolve()) if "/" in value else shutil.which(value)
    if not path or not os.path.isfile(path) or not os.access(path, os.X_OK):
        raise BenchmarkError("executable not found; check binary paths and PATH")
    return path


def load_config(path):
    try:
        config = json.loads(path.read_text())
    except (OSError, ValueError):
        raise BenchmarkError("cannot read benchmark JSON config") from None
    required = {"xray_rs_bin", "xray_core_bin", "target_url", "server"}
    defaults = {"rounds": 3, "duration_seconds": 30, "startup_timeout_seconds": 10}
    if not isinstance(config, dict) or required - config.keys() or config.keys() - required - defaults.keys():
        raise BenchmarkError("config requires xray_rs_bin, xray_core_bin, target_url, server; unknown fields rejected")
    config = defaults | config
    for key in defaults:
        value = config[key]
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or value <= 0):
            raise BenchmarkError(f"{key} must be a finite positive number")
    if not isinstance(config["rounds"], int):
        raise BenchmarkError("rounds must be an integer")
    try:
        target = urlsplit(config["target_url"])
        if target.scheme != "https" or not target.hostname or target.username or target.password:
            raise ValueError()
        target.port
    except (ValueError, TypeError, AttributeError):
        raise BenchmarkError("target_url must be an HTTPS URL without credentials") from None
    config["server"] = parse_server(config["server"])
    for key in ("xray_rs_bin", "xray_core_bin"):
        config[key] = executable(config[key], path.resolve().parent)
    config["curl"] = executable("curl", path.resolve().parent)
    return config


def proxy_config(server, port, core):
    trojan = {k: server[k] for k in ("address", "port", "password")}
    settings = {"servers": [trojan]} if core == "xray-core" else trojan
    return {
        "log": {"loglevel": "warning"} if core == "xray-core" else {"level": "warn"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "http", "tag": "benchmark"}],
        "outbounds": [{"protocol": "trojan", "tag": "proxy", "settings": settings,
                       "streamSettings": {
                           "network": "grpc", "security": "tls",
                           "tlsSettings": {"serverName": server["sni"], "alpn": server["alpn"],
                                           "allowInsecure": False},
                           "grpcSettings": {"serviceName": server["service"], "multiMode": False,
                                            "authority": server["authority"]},
                       }}],
    }


@contextlib.contextmanager
def managed_process(command, **kwargs):
    process = subprocess.Popen(command, **kwargs)
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        process.wait()


def wait_ready(process, port, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise BenchmarkError("core exited before its HTTP proxy was ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise BenchmarkError("core HTTP proxy startup timed out")


def parse_result(returncode, output):
    try:
        data = json.loads(output)
        size, elapsed = data["size_download"], data["time_total"]
        status = int(data["http_code"])
        if (returncode not in (0, 28) or status < 200 or status >= 300
                or isinstance(size, bool) or isinstance(elapsed, bool)
                or not isinstance(size, (int, float)) or not isinstance(elapsed, (int, float))
                or not math.isfinite(size) or not math.isfinite(elapsed) or size <= 0 or elapsed <= 0
                or (returncode == 28 and data.get("time_starttransfer", 0) <= 0)):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise BenchmarkError(f"download failed (curl exit {returncode}); no valid throughput sample") from None
    return {"bytes": size, "seconds": elapsed, "mib_s": size / elapsed / 1024**2,
            "mbps": size / elapsed * 8 / 1_000_000, "limited": returncode == 28}


def sample(config, core):
    with tempfile.TemporaryDirectory(prefix="xray-benchmark-") as directory:
        directory = Path(directory)
        # The listener must close before the core binds; fail rather than reuse a busy port.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        path = directory / "config.json"
        with open(path, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as file:
            json.dump(proxy_config(config["server"], port, core), file)
        binary = config["xray_rs_bin" if core == "xray-rs" else "xray_core_bin"]
        command = [binary, "run", "-c" if core == "xray-rs" else "-config", str(path)]
        environment = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
        with (directory / "core.log").open("wb") as log:
            with managed_process(command, stdout=log, stderr=log) as process:
                try:
                    wait_ready(process, port, config["startup_timeout_seconds"])
                except BenchmarkError as error:
                    detail = (directory / "core.log").read_text(errors="replace")[-2000:]
                    detail = detail.replace(config["server"]["password"], "<redacted>")
                    raise BenchmarkError(f"{error}\n{detail}") from None
                curl = [config["curl"], "--disable", "--silent", "--show-error", "--fail", "--location",
                        "--proto", "=https", "--proto-redir", "=https", "--noproxy", "",
                        "--proxy", f"http://127.0.0.1:{port}", "--output", os.devnull,
                        "--header", "Accept-Encoding: identity", "--connect-timeout", "10",
                        "--max-time", str(config["duration_seconds"]), "--write-out", "%{json}",
                        "--url", config["target_url"]]
                with managed_process(curl, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, env=environment) as download:
                    try:
                        output, errors = download.communicate(timeout=config["duration_seconds"] + 5)
                    except subprocess.TimeoutExpired:
                        raise BenchmarkError("curl did not stop within its time limit") from None
                    try:
                        result = parse_result(download.returncode, output)
                    except BenchmarkError as error:
                        detail = errors[-1000:] + (directory / "core.log").read_text(errors="replace")[-2000:]
                        detail = detail.replace(config["server"]["password"], "<redacted>")
                        raise BenchmarkError(f"{error}\n{detail}") from None
                if process.poll() is not None:
                    raise BenchmarkError("core exited during download; sample discarded")
                return result


def run(config):
    print("Trojan + gRPC + TLS; sequential single-stream HTTPS downloads", flush=True)
    print("xray-rs binary:", config["xray_rs_bin"], flush=True)
    print("xray-core binary:", config["xray_core_bin"], flush=True)
    if config["server"]["fingerprint"]:
        print("Note: URI fp ignored for BOTH cores; xray-rs has no browser TLS fingerprint support.", flush=True)
    results = {"xray-rs": [], "xray-core": []}
    for index in range(config["rounds"]):
        order = list(results) if index % 2 == 0 else list(reversed(results))
        for core in order:
            try:
                result = sample(config, core)
            except (BenchmarkError, OSError) as error:
                if isinstance(error, OSError):
                    error = "cannot launch benchmark process or access temporary files"
                raise BenchmarkError(f"round {index + 1} {core}: {error}") from None
            results[core].append(result["mib_s"])
            print(f"round {index + 1} {core}: {result['bytes']:.0f} bytes / {result['seconds']:.3f}s"
                  f" = {result['mib_s']:.3f} MiB/s ({result['mbps']:.3f} Mbps)"
                  f" [{'time limit' if result['limited'] else 'complete'}]", flush=True)
    medians = {core: statistics.median(values) for core, values in results.items()}
    for core, value in medians.items():
        print(f"{core} median: {value:.3f} MiB/s ({value * 1024**2 * 8 / 1_000_000:.3f} Mbps)")
    print(f"xray-rs / xray-core: {medians['xray-rs'] / medians['xray-core']:.3f}x")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="benchmark JSON config")
    args = parser.parse_args()
    # Convert termination to stack unwinding so both child processes are reaped.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        run(load_config(args.config))
    except BenchmarkError as error:
        print(f"benchmark error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("benchmark interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
