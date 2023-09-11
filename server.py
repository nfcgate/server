#!/usr/bin/env python3
import socket
import socketserver
import struct
import sys
import datetime
import ssl

HOST = "0.0.0.0"
PORT = 5566


class PluginHandler:
    def __init__(self):
        self.plugin_list = []

        for modname in sys.argv[1:]:
            self.plugin_list.append((modname, __import__("plugins.mod_%s" % modname, fromlist=["plugins"])))
            print("Loaded", "mod_%s" % modname)

    def filter(self, client, data):
        for modname, plugin in self.plugin_list:
            if type(data) == list:
                first = data[0]
            else:
                first = data
            first = plugin.handle_data(lambda *x: client.log(*x, tag=modname), first, client.state)
            if type(data) == list:
                data = [first] + data[1:]
            else:
                data = first

        return data


class NFCGateClientHandler(socketserver.StreamRequestHandler):
    def __init__(self, request, client_address, srv):
        super().__init__(request, client_address, srv)

    def log(self, *args, tag="server"):
        self.server.log(*args, origin=self.client_address, tag=tag)

    def setup(self):
        super().setup()

        self.session = None
        self.state = {}
        self.request.settimeout(300)
        self.log("server", "connected")

    def handle(self):
        super().handle()

        while True:
            try:
                msg_len_data = self.rfile.read(5)
            except socket.timeout:
                self.log("server", "Timeout")
                break
            if len(msg_len_data) < 5:
                break

            msg_len, session = struct.unpack("!IB", msg_len_data)
            data = self.rfile.read(msg_len)
            self.log("server", "data:", bytes(data))

            # no data was sent or no session number supplied and none set yet
            if msg_len == 0 or session == 0 and self.session is None:
                break

            # change in session number detected
            if self.session != session:
                # remove from old association
                self.server.remove_client(self, self.session)
                # update and add association
                self.session = session
                self.server.add_client(self, session)

            # allow plugins to filter data before sending it to all clients in the session
            self.server.send_to_clients(self.session, self.server.plugins.filter(self, data), self)

    def finish(self):
        super().finish()

        self.server.remove_client(self, self.session)
        self.log("server", "disconnected")


class NFCGateServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, request_handler, bind_and_activate=True, use_tls=False):
        self.allow_reuse_address = True
        super().__init__(server_address, request_handler, bind_and_activate)
        self.use_tls = use_tls
        if self.use_tls:
            # Setting up the SSL context
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.load_cert_chain(certfile="certs/server.crt", keyfile="certs/server.key")

            # For security consideration, enforce TLS 1.2 and above
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

        self.clients = {}
        self.plugins = PluginHandler()
        self.log("NFCGate server listening on", server_address)

        # Load certificate and print fingerprint
        with open("certs/server.crt", "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            fingerprint = cert.fingerprint(hashes.SHA256())
            self.log("TLS mode is", f"ENABLED, Certificate Fingerprint: {fingerprint.hex()}" if use_tls else "disabled")

    def get_request(self):
        new_socket, from_address = super().get_request()
        if self.use_tls:
            ssl_socket = self.ssl_context.wrap_socket(new_socket, server_side=True)
            return ssl_socket, from_address
        else:
            return new_socket, from_address

    def log(self, *args, origin="0", tag="server"):
        print(datetime.datetime.now(), "[" + tag + "]", origin, *args)

    def add_client(self, client, session):
        if session is None:
            return

        if session not in self.clients:
            self.clients[session] = []

        self.clients[session].append(client)
        client.log("joined session", session)

    def remove_client(self, client, session):
        if session is None or session not in self.clients:
            return

        self.clients[session].remove(client)
        client.log("left session", session)

    def send_to_clients(self, session, msgs, origin):
        if session is None or session not in self.clients:
            return

        for client in self.clients[session]:
            # do not send message back to originator
            if client is origin:
                continue

            if type(msgs) != list:
                msgs = [msgs]

            for msg in msgs:
                client.wfile.write(int.to_bytes(len(msg), 4, byteorder='big'))
                client.wfile.write(msg)

        self.log("Publish reached", len(self.clients[session]) - 1, "clients")


if __name__ == "__main__":
    # If certs directory is not found, then create
    # it and generate self-signed ecc 256 certificates without calling external executables
    import os

    if not os.path.exists("certs"):
        os.makedirs("certs")

    if not os.path.exists("certs/server.crt") or not os.path.exists("certs/server.key"):
        import OpenSSL
        from OpenSSL import crypto
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

        # Generate a key pair
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # Write our key to disk for safe keeping
        with open("certs/server.key", "wb") as f:
            f.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

        # Various details about who we are. For a self-signed certificate the
        # subject and issuer are always the same.
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NFCGate"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"NFCGate_Server"),
        ])

        # Because this is self-signed, the issuer is always the subject
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10 * 365))
            .sign(key, hashes.SHA256(), default_backend())
        )

        # Write our certificate out to disk.
        with open("certs/server.crt", "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))

    try:
        # Use Plain TCP
        NFCGateServer((HOST, PORT), NFCGateClientHandler).serve_forever()

        # Use TLS
        # NFCGateServer((HOST, PORT), NFCGateClientHandler, use_tls=True).serve_forever()
    except KeyboardInterrupt:
        print("Server Stopped")
