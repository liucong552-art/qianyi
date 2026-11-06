"""Concurrent loopback-only TLS 1.3 destination for synthetic Reality tests."""
import contextlib
import socketserver
import ssl
import threading


@contextlib.contextmanager
def tls_target(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    context.set_ecdh_curve('X25519')
    context.set_alpn_protocols(['h2', 'http/1.1'])

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            try:
                # Handshake in the connection's thread, never in accept().
                # Xray probes multiple ALPN/CCS variants concurrently; one
                # unfinished handshake must not block a real client behind it.
                with context.wrap_socket(self.request, server_side=True) as tls:
                    while tls.recv(4096):
                        pass
            except OSError:
                # Closed raw health probes and intentionally invalid CCS are
                # expected. They must not terminate the destination listener.
                pass

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with Server(('127.0.0.1', 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join(timeout=3)
