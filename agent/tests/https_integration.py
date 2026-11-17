#!/usr/bin/env python3
"""Exercise the real C sender against temporary localhost HTTPS receivers."""

import errno
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class LocalSocketDenied(Exception):
    pass


class Receiver(HTTPServer):
    def __init__(self, cert, key, status):
        self.requests = []
        self.status = status
        try:
            super().__init__(("127.0.0.1", 0), Handler)
        except PermissionError as exc:
            if exc.errno == errno.EPERM:
                raise LocalSocketDenied from exc
            raise
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.requests.append((self.path, self.headers.get("Content-Type"), body))
        self.send_response(self.server.status)
        self.end_headers()

    def log_message(self, *_args):
        pass


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE)


def certificate(directory, name, ca_cert, ca_key, ip):
    key = directory / f"{name}.key"
    csr = directory / f"{name}.csr"
    cert = directory / f"{name}.crt"
    ext = directory / f"{name}.ext"
    ext.write_text("basicConstraints=critical,CA:FALSE\n"
                   "keyUsage=digitalSignature,keyEncipherment\n"
                   "extendedKeyUsage=serverAuth\n"
                   f"subjectAltName=IP:{ip}\n")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
            "-subj", "/CN=fixture receiver", "-keyout", key, "-out", csr)
    openssl("x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
            "-CAcreateserial", "-out", cert, "-days", "1", "-sha256", "-extfile", ext)
    return cert, key


def call(helper, command, state, *args, ca=None):
    env = os.environ.copy()
    env.pop("HP_TEST_CA", None)
    if ca:
        env["HP_TEST_CA"] = str(ca)
    result = subprocess.run([str(helper), command, str(state), *map(str, args)],
                            env=env, text=True, capture_output=True, check=True, timeout=40)
    return result.stdout.strip()


def send(helper, state, receiver, ca):
    return int(call(helper, "send", state, "127.0.0.1", receiver.server_port, ca=ca))


def pending(helper, state):
    return int(call(helper, "count", state))


def assert_payload(receiver):
    assert len(receiver.requests) == 1, receiver.requests
    path, content_type, body = receiver.requests[0]
    assert path == "/events", path
    assert content_type == "application/json", content_type
    report = json.loads(body)
    assert report["schema_version"] == 1, report
    assert report["agent_id"] == "https-fixture-agent", report
    assert report["source"] == "status", report
    assert report["operation"] == "fixture_event", report
    assert report["path"] == "/fixture/path", report
    assert report["content"] == "fixture payload\n", report
    assert len(report["report_id"]) == 64, report
    return report["report_id"]


def main(helper):
    # Probe first: restricted sandboxes cannot run any local HTTPS fixture.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
    except PermissionError as exc:
        if exc.errno == errno.EPERM:
            raise LocalSocketDenied from exc
        raise

    with tempfile.TemporaryDirectory(prefix="hp-https-") as temp:
        directory = Path(temp)
        ca_key, ca_cert = directory / "ca.key", directory / "ca.crt"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-days", "1", "-subj", "/CN=Fixture CA", "-keyout", ca_key,
                "-out", ca_cert, "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        other_key, other_cert = directory / "other.key", directory / "other.crt"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-days", "1", "-subj", "/CN=Other CA", "-keyout", other_key,
                "-out", other_cert, "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        valid_cert, valid_key = certificate(directory, "valid", ca_cert, ca_key, "127.0.0.1")
        wrong_cert, wrong_key = certificate(directory, "wrong-ip", ca_cert, ca_key, "127.0.0.2")
        untrusted_cert, untrusted_key = certificate(directory, "untrusted", other_cert,
                                                    other_key, "127.0.0.1")

        success_state = directory / "success-state"
        call(helper, "queue", success_state)
        assert pending(helper, success_state) == 1
        receiver = Receiver(valid_cert, valid_key, 200)
        try:
            assert send(helper, success_state, receiver, ca_cert) == 1
            assert_payload(receiver)
            assert pending(helper, success_state) == 0
        finally:
            receiver.close()

        retry_state = directory / "retry-state"
        call(helper, "queue", retry_state)
        receiver = Receiver(valid_cert, valid_key, 503)
        try:
            assert send(helper, retry_state, receiver, ca_cert) == 0
            original_id = assert_payload(receiver)
            assert pending(helper, retry_state) == 1
        finally:
            receiver.close()
        receiver = Receiver(valid_cert, valid_key, 204)
        try:
            assert send(helper, retry_state, receiver, ca_cert) == 1
            assert assert_payload(receiver) == original_id
            assert pending(helper, retry_state) == 0
        finally:
            receiver.close()

        for label, cert, key in (("untrusted", untrusted_cert, untrusted_key),
                                 ("wrong-ip", wrong_cert, wrong_key)):
            state = directory / f"{label}-state"
            call(helper, "queue", state)
            receiver = Receiver(cert, key, 200)
            try:
                assert send(helper, state, receiver, ca_cert) == 0, label
                assert pending(helper, state) == 1, label
                assert receiver.requests == [], label
            finally:
                receiver.close()
        print("PASS local HTTPS integration: trusted IP, HTTP retry, untrusted CA, wrong IP SAN")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} HELPER")
    try:
        main(Path(sys.argv[1]).resolve())
    except LocalSocketDenied:
        print("SKIP local HTTPS integration: localhost socket creation/bind denied (EPERM)")
