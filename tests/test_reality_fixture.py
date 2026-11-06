"""Real local TLS sockets; no Xray, root or changes to host networking."""
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import unittest
from tls_target import tls_target


class TLSTargetTests(unittest.TestCase):
    def test_stalled_handshake_does_not_block_another_client(self):
        with tempfile.TemporaryDirectory() as directory:
            cert = Path(directory)/'tls.crt'
            key = Path(directory)/'tls.key'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                            '-nodes', '-days', '1', '-subj', '/CN=tls.example.com',
                            '-addext', 'subjectAltName=DNS:tls.example.com',
                            '-keyout', str(key), '-out', str(cert)],
                           check=True, capture_output=True)
            client = ssl.create_default_context(cafile=str(cert))
            client.minimum_version = ssl.TLSVersion.TLSv1_3
            client.set_alpn_protocols(['h2'])
            with tls_target(cert, key) as port:
                with socket.create_connection(('127.0.0.1', port), timeout=2):
                    with socket.create_connection(('127.0.0.1', port), timeout=2) as raw:
                        with client.wrap_socket(raw, server_hostname='tls.example.com') as tls:
                            self.assertEqual(tls.version(), 'TLSv1.3')
                            self.assertEqual(tls.selected_alpn_protocol(), 'h2')
