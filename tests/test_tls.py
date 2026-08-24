"""TLS tests against a real local server.

Mutation testing during the audit showed the whole suite passing with
``ssl.create_default_context()`` swapped for ``ssl._create_unverified_context()``
and with ``server_hostname`` dropped from ``wrap_socket``. Every transport test
stubbed ``_openers``, so none of the TLS code ever ran. These tests exercise it.
"""

import datetime
import socket
import ssl
import threading

import pytest

from technocore.errors import TransportError
from technocore.transport import Transport, _connect_v4

cryptography = pytest.importorskip("cryptography")
from cryptography import x509                                     # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa         # noqa: E402
from cryptography.x509.oid import NameOID                         # noqa: E402


def _self_signed(tmp_path, common_name="localhost"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]),
                       critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return str(cert_path), str(key_path)


class _TLSServer:
    """A one-shot TLS listener that records the SNI name it was offered."""

    def __init__(self, cert, key):
        self.sni = []
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.context.set_servername_callback(self._record)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _record(self, sslsock, server_name, context):
        self.sni.append(server_name)

    def _serve(self):
        while True:
            try:
                client, _addr = self.sock.accept()
            except OSError:
                return
            try:
                with self.context.wrap_socket(client, server_side=True) as tls:
                    tls.recv(1024)
                    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except (ssl.SSLError, OSError):
                pass
            finally:
                try:
                    client.close()
                except OSError:
                    pass

    def close(self):
        self.sock.close()


@pytest.fixture
def tls_server(tmp_path):
    cert, key = _self_signed(tmp_path)
    server = _TLSServer(cert, key)
    yield server
    server.close()


def test_a_self_signed_certificate_is_rejected(tls_server):
    # This is the test that kills an _create_unverified_context() regression.
    transport = Transport("t", timeout=5, attempts=1, backoff=0,
                          sleep=lambda _s: None)
    with pytest.raises(TransportError) as info:
        transport.get("https://localhost:%d/r/lobby" % tls_server.port)
    assert "CERTIFICATE_VERIFY_FAILED" in str(info.value)


def test_the_client_offers_sni(tls_server):
    # Dropping server_hostname from wrap_socket disables hostname checking
    # silently. If SNI never reaches the server, that mutation has happened.
    transport = Transport("t", timeout=5, attempts=1, backoff=0,
                          sleep=lambda _s: None)
    with pytest.raises(TransportError):
        transport.get("https://localhost:%d/r/lobby" % tls_server.port)
    # Both openers are tried for an idempotent read, so the count varies;
    # what matters is that the name was offered at all, and correctly.
    assert tls_server.sni and set(tls_server.sni) == {"localhost"}


@pytest.mark.parametrize("prefer_ipv4", [True, False])
def test_both_openers_verify_certificates(prefer_ipv4):
    transport = Transport("t", prefer_ipv4=prefer_ipv4)
    for opener in (transport._v4_opener, transport._default_opener):
        contexts = [getattr(h, "_context", None) for h in opener.handlers]
        contexts = [c for c in contexts if c is not None]
        assert contexts, "no ssl context found on the opener"
        for context in contexts:
            assert context.check_hostname is True
            assert context.verify_mode == ssl.CERT_REQUIRED


def test_connect_v4_returns_an_ipv4_socket():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        sock = _connect_v4("127.0.0.1", listener.getsockname()[1], 5)
        try:
            assert sock.family == socket.AF_INET
        finally:
            sock.close()
    finally:
        listener.close()


def test_connect_v4_resolves_the_global_timeout_sentinel():
    # http.client passes a module-level sentinel to mean "use the default";
    # handing that straight to settimeout raises TypeError.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        sock = _connect_v4("127.0.0.1", listener.getsockname()[1],
                           socket._GLOBAL_DEFAULT_TIMEOUT)
        sock.close()
    finally:
        listener.close()


def test_a_host_with_no_ipv4_address_fails_cleanly():
    with pytest.raises(OSError):
        _connect_v4("ipv6.google.com.invalid", 443, 2)
