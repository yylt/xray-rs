"""Offline benchmark tests; fake programs only connect to loopback."""

import contextlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

import benchmark


URI = "trojan://private%40password@example.invalid:443?security=tls&type=grpc&serviceName=service"


class BenchmarkTests(unittest.TestCase):
    def test_server_defaults_and_options(self):
        server = benchmark.parse_server(URI)
        self.assertEqual(server, {
            "address": "example.invalid", "port": 443,
            "password": "private@password", "sni": "example.invalid",
            "alpn": ["h2"], "authority": "example.invalid", "service": "service",
            "fingerprint": None,
        })
        server = benchmark.parse_server(
            URI.replace("serviceName=service", "serviceName=my-service")
            + "&sni=tls.invalid&alpn=h2,http%2F1.1&authority=grpc.invalid&fp=chrome"
        )
        self.assertEqual(server["sni"], "tls.invalid")
        self.assertEqual(server["authority"], "grpc.invalid")
        self.assertEqual(server["alpn"], ["h2", "http/1.1"])
        self.assertEqual(server["service"], "my-service")
        self.assertEqual(server["fingerprint"], "chrome")
        self.assertEqual(benchmark.parse_server(URI + "&sni=tls.invalid")["authority"],
                         "tls.invalid")

    def test_rejected_uris_do_not_disclose_password(self):
        invalid = [None, "", URI.replace("trojan:", "https:"),
                   URI.replace(":443", ""), URI.replace(":443", ":70000"),
                   URI.replace("private%40password", ""),
                   URI.replace("private%40password", "private:password"),
                   URI.replace("?", "/path?"), URI.replace("tls", "none"),
                   URI.replace("grpc", "tcp"), URI + "&unknown=password",
                   URI + "&type=grpc", URI + "&sni=", URI + "&sni=%0A",
                   URI + "&broken", URI.replace("&serviceName=service", ""),
                   URI.replace("serviceName=service", "serviceName=a%2Fb"),
                   URI + "&alpn=http%2F1.1", URI + "&alpn=h2,"]
        for uri in invalid:
            with self.subTest(uri=uri):
                with self.assertRaises(benchmark.BenchmarkError) as raised:
                    benchmark.parse_server(uri)
                self.assertNotIn("private", str(raised.exception))
                self.assertNotIn("password", str(raised.exception))

    def test_native_proxy_configs(self):
        server = benchmark.parse_server(URI + "&fp=chrome")
        for core in ("xray-rs", "xray-core"):
            with self.subTest(core=core):
                config = benchmark.proxy_config(server, 12345, core)
                self.assertEqual(config["log"], {"level": "warn"} if core == "xray-rs"
                                 else {"loglevel": "warning"})
                self.assertEqual(config["inbounds"], [{"listen": "127.0.0.1",
                    "port": 12345, "protocol": "http", "tag": "benchmark"}])
                outbound = config["outbounds"][0]
                trojan = {"address": "example.invalid", "port": 443,
                          "password": "private@password"}
                self.assertEqual(outbound["protocol"], "trojan")
                self.assertEqual(outbound["settings"], trojan if core == "xray-rs"
                                 else {"servers": [trojan]})
                self.assertEqual(outbound["streamSettings"], {
                    "network": "grpc", "security": "tls",
                    "tlsSettings": {"serverName": "example.invalid", "alpn": ["h2"],
                                    "allowInsecure": False},
                    "grpcSettings": {"serviceName": "service", "multiMode": False,
                                     "authority": "example.invalid"},
                })
                self.assertNotIn("fingerprint", json.dumps(config))

    def test_config_defaults_paths_and_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "core"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o700)
            path = root / "benchmark.json"
            valid = {"xray_rs_bin": "./core", "xray_core_bin": "./core",
                     "target_url": "https://target.invalid/file", "server": URI}
            with mock.patch.object(benchmark.shutil, "which", return_value=str(binary)):
                path.write_text(json.dumps(valid))
                config = benchmark.load_config(path)
                self.assertEqual(config["rounds"], 3)
                self.assertEqual(config["duration_seconds"], 30)
                self.assertEqual(config["startup_timeout_seconds"], 10)
                self.assertEqual(config["xray_rs_bin"], str(binary))
                self.assertEqual(config["xray_core_bin"], str(binary))
                self.assertEqual(config["server"]["password"], "private@password")
                invalid = [[], {}, valid | {"extra": 1}]
                invalid += [valid | {key: value}
                            for key in ("rounds", "duration_seconds", "startup_timeout_seconds")
                            for value in (True, 0, -1, "1", None, float("nan"), float("inf"))]
                invalid += [valid | {"rounds": 1.5}]
                invalid += [valid | {"target_url": value} for value in
                            (None, "http://target.invalid", "https:///file",
                             "https://user:private@target.invalid", "https://host:bad")]
                invalid += [valid | {"server": "trojan://private@bad"}]
                invalid += [valid | {"xray_rs_bin": value} for value in
                            (None, "", "./missing")]
                for value in invalid:
                    with self.subTest(config=value):
                        path.write_text(json.dumps(value))
                        with self.assertRaises(benchmark.BenchmarkError) as raised:
                            benchmark.load_config(path)
                        self.assertNotIn("private", str(raised.exception))
                path.write_text("not JSON")
                with self.assertRaises(benchmark.BenchmarkError):
                    benchmark.load_config(path)
                with self.assertRaises(benchmark.BenchmarkError):
                    benchmark.load_config(root / "missing.json")
                binary.chmod(0o600)
                with self.assertRaises(benchmark.BenchmarkError):
                    benchmark.executable("./core", root)
        with mock.patch.object(benchmark.shutil, "which", return_value=None):
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.executable("missing-program", Path.cwd())

    def test_curl_valid_completed_and_timed_samples(self):
        data = {"size_download": 2 * 1024**2, "time_total": 2,
                "http_code": "206", "time_starttransfer": 0.1}
        for code in (0, 28):
            with self.subTest(code=code):
                result = benchmark.parse_result(code, json.dumps(data))
                self.assertEqual(result, {"bytes": 2 * 1024**2, "seconds": 2,
                    "mib_s": 1, "mbps": 8.388608, "limited": code == 28})

    def test_curl_invalid_results(self):
        valid = {"size_download": 1024, "time_total": 1, "http_code": 200}
        invalid = [(0, "not JSON"), (0, "null"), (0, "[]"), (0, "{}")]
        invalid += [(code, json.dumps(valid)) for code in (7, 22, 28, -15)]
        invalid += [(0, json.dumps(valid | {"http_code": code}))
                    for code in (0, 199, 300, 404, 500, "bad")]
        invalid += [(0, json.dumps(valid | {key: value}))
                    for key in ("size_download", "time_total")
                    for value in (True, 0, -1, "2", None, float("nan"), float("inf"))]
        invalid += [(28, json.dumps(valid | {"time_starttransfer": value}))
                    for value in (0, -1, None, "bad")]
        for code, output in invalid:
            with self.subTest(code=code, output=output):
                with self.assertRaises(benchmark.BenchmarkError):
                    benchmark.parse_result(code, output)

    def test_run_alternates_order_and_reports_medians(self):
        config = {"rounds": 3, "xray_rs_bin": "/fake/rs", "xray_core_bin": "/fake/core",
                  "server": benchmark.parse_server(URI + "&fp=chrome")}
        rates = [1, 4, 6, 3, 2, 5]
        samples = [{"bytes": rate * 1024**2, "seconds": 1, "mib_s": rate,
                    "mbps": rate * 8.388608, "limited": index == 0}
                   for index, rate in enumerate(rates)]
        output = io.StringIO()
        with mock.patch.object(benchmark, "sample", side_effect=samples) as sample:
            with contextlib.redirect_stdout(output):
                benchmark.run(config)
        self.assertEqual([call.args[1] for call in sample.call_args_list],
                         ["xray-rs", "xray-core", "xray-core", "xray-rs",
                          "xray-rs", "xray-core"])
        self.assertIn("xray-rs median: 2.000 MiB/s", output.getvalue())
        self.assertIn("xray-core median: 5.000 MiB/s", output.getvalue())
        self.assertIn("xray-rs / xray-core: 0.400x", output.getvalue())
        self.assertIn("URI fp ignored for BOTH cores", output.getvalue())
        self.assertIn("[time limit]", output.getvalue())

    def test_run_failure_stops_without_medians_or_sensitive_os_error(self):
        config = {"rounds": 3, "xray_rs_bin": "/fake/rs", "xray_core_bin": "/fake/core",
                  "server": benchmark.parse_server(URI)}
        for error in (benchmark.BenchmarkError("download failed"), OSError("private@password")):
            with self.subTest(error=type(error).__name__):
                output = io.StringIO()
                with mock.patch.object(benchmark, "sample", side_effect=error) as sample:
                    with contextlib.redirect_stdout(output):
                        with self.assertRaises(benchmark.BenchmarkError) as raised:
                            benchmark.run(config)
                self.assertEqual(sample.call_count, 1)
                self.assertIn("round 1 xray-rs:", str(raised.exception))
                self.assertNotIn("private", str(raised.exception))
                self.assertNotIn("median", output.getvalue())

    def test_managed_process_reaps_on_normal_and_exceptional_exit(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                try:
                    with benchmark.managed_process(
                            [sys.executable, "-c", "import time; time.sleep(60)"]) as process:
                        if fail:
                            raise RuntimeError("body failed")
                except RuntimeError:
                    if not fail:
                        raise
                self.assertIsNotNone(process.poll())
                with self.assertRaises(ChildProcessError):
                    os.waitpid(process.pid, os.WNOHANG)

    def test_managed_process_kills_after_terminate_timeout(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("core", 3), -9]
        with mock.patch.object(benchmark.subprocess, "Popen", return_value=process):
            with benchmark.managed_process(["core"]):
                pass
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_args_list, [mock.call(timeout=3), mock.call()])

    def test_wait_ready_exit_and_timeout(self):
        process = mock.Mock()
        process.poll.return_value = 1
        with self.assertRaisesRegex(benchmark.BenchmarkError, "exited"):
            benchmark.wait_ready(process, 1, 0.1)
        process.poll.return_value = None
        with self.assertRaisesRegex(benchmark.BenchmarkError, "timed out"):
            benchmark.wait_ready(process, 1, 0)


class FakeProcessIntegrationTests(unittest.TestCase):
    def test_cli_fake_cores_and_curl_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "events.jsonl"
            core = root / "fake-core"
            curl = root / "curl"
            core.write_text("#!" + sys.executable + "\n" + textwrap.dedent('''
                import json, os, pathlib, socket, sys
                path = pathlib.Path(sys.argv[-1])
                config = json.loads(path.read_text())
                inbound = config["inbounds"][0]
                with open(os.environ["BENCHMARK_TEST_EVENTS"], "a") as out:
                    out.write(json.dumps({"kind": "core", "pid": os.getpid(),
                        "args": sys.argv[1:], "config": config,
                        "mode": path.stat().st_mode & 0o777}) + "\\n")
                with socket.socket() as listener:
                    listener.bind((inbound["listen"], inbound["port"]))
                    listener.listen()
                    while True:
                        connection, _ = listener.accept()
                        with connection:
                            request = connection.recv(4096)
                            if request:
                                connection.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nOK")
            '''))
            curl.write_text("#!" + sys.executable + "\n" + textwrap.dedent('''
                import json, os, socket, sys
                from urllib.parse import urlsplit
                args = sys.argv[1:]
                proxy = urlsplit(args[args.index("--proxy") + 1])
                assert proxy.hostname == "127.0.0.1"
                assert not any(key.lower().endswith("_proxy") for key in os.environ)
                with socket.create_connection((proxy.hostname, proxy.port), timeout=2) as connection:
                    connection.sendall(b"GET / HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n")
                    assert b"200 OK" in connection.recv(4096)
                with open(os.environ["BENCHMARK_TEST_EVENTS"], "a") as out:
                    out.write(json.dumps({"kind": "curl", "pid": os.getpid(), "args": args}) + "\\n")
                print(json.dumps({"size_download": 2097152, "time_total": 2,
                                  "http_code": 200, "time_starttransfer": 0.1}))
                mode = os.environ.get("BENCHMARK_TEST_CURL_EXIT", "0")
                if mode == "hang":
                    import time
                    time.sleep(60)
                sys.exit(int(mode))
            '''))
            core.chmod(0o700)
            curl.chmod(0o700)
            path = root / "benchmark.json"
            path.write_text(json.dumps({"xray_rs_bin": "./fake-core",
                "xray_core_bin": "./fake-core", "target_url": "https://target.invalid/file",
                "server": URI, "rounds": 2, "duration_seconds": 0.1,
                "startup_timeout_seconds": 3}))
            environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ.get("PATH", ""),
                               BENCHMARK_TEST_EVENTS=str(events), HTTPS_PROXY="http://unusable.invalid")
            command = [sys.executable, str(Path(benchmark.__file__).resolve()), "--config", str(path)]
            for exit_code in (0, 28, 22, "hang"):
                with self.subTest(curl_exit=exit_code):
                    events.write_text("")
                    environment["BENCHMARK_TEST_CURL_EXIT"] = str(exit_code)
                    completed = subprocess.run(command, capture_output=True, text=True,
                                               env=environment, timeout=20)
                    self.assertEqual(completed.returncode, 1 if exit_code in (22, "hang") else 0,
                                     completed.stderr)
                    self.assertNotIn("private", completed.stdout + completed.stderr)
                    records = [json.loads(line) for line in events.read_text().splitlines()]
                    cores = [record for record in records if record["kind"] == "core"]
                    downloads = [record for record in records if record["kind"] == "curl"]
                    self.assertEqual(len(cores), 1 if exit_code in (22, "hang") else 4)
                    self.assertEqual(len(downloads), len(cores))
                    for record in cores:
                        self.assertEqual(record["mode"], 0o600)
                        self.assertFalse(Path(record["args"][-1]).exists())
                        with self.assertRaises(ProcessLookupError):
                            os.kill(record["pid"], 0)
                        port = record["config"]["inbounds"][0]["port"]
                        with socket.socket() as probe:
                            self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0)
                    if exit_code in (22, "hang"):
                        self.assertIn("round 1 xray-rs", completed.stderr)
                        self.assertNotIn("median", completed.stdout)
                    else:
                        self.assertEqual([record["args"][1] for record in cores],
                                         ["-c", "-config", "-config", "-c"])
                        self.assertIn("xray-rs median: 1.000 MiB/s", completed.stdout)
                        self.assertIn("xray-core median: 1.000 MiB/s", completed.stdout)
                        self.assertIn("[time limit]" if exit_code == 28 else "[complete]",
                                      completed.stdout)
                    for record in downloads:
                        args = record["args"]
                        self.assertEqual(args[0], "--disable")
                        for flag in ("--proto", "--proto-redir"):
                            self.assertEqual(args[args.index(flag) + 1], "=https")
                        self.assertEqual(args[args.index("--noproxy") + 1], "")
                        self.assertEqual(args[args.index("--max-time") + 1], "0.1")


if __name__ == "__main__":
    unittest.main()
