#!/usr/bin/env python 

import socketserver
import struct

HOST = "0.0.0.0"
PORT = 13374


class NFCGateClientHandler(socketserver.StreamRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.session = None

    def setup(self):
        super().setup()

        self.session = None
        print(self.client_address, "new client")

    def handle(self):
        super().handle()

        while True:
            msg_len, session = struct.unpack("!IB", self.rfile.read(5))
            print(self.client_address, "Got message of", msg_len, "bytes")
            if msg_len == 0:
                break

            data = self.rfile.read(msg_len)
            print(self.client_address, "data:", bytes(data))

            # no session number supplied and none set yet
            if session == 0 and self.session is None:
                continue

            # change in session number detected
            if self.session != session:
                # remove from old association
                self.server.remove_client(self, self.session)
                # update and add association
                self.session = session
                self.server.add_client(self, session)

            self.server.send_to_clients(self.session, data, self)

    def finish(self):
        super().finish()

        self.server.remove_client(self, self.session)
        print(self.client_address, "disconnected")


class NFCGateServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        self.allow_reuse_address = True
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.clients = {}

    def add_client(self, client, session):
        if session is None:
            return

        if session not in self.clients:
            self.clients[session] = []
        self.clients[session].append(client)

        print(self, client.client_address, "added to session", session)

    def remove_client(self, client, session):
        if session is None or session not in self.clients:
            return

        self.clients[session].remove(client)
        print(self, client.client_address, "removed from session", session)

    def send_to_clients(self, session, msg, origin):
        if session is None or session not in self.clients:
            return

        for client in self.clients[session]:
            # do not send message back to originator
            if client is origin:
                continue

            data = int.to_bytes(len(msg), 4, byteorder='big') + msg
            client.wfile.write(data)

        print(self, "Sent message to", len(self.clients[session]), "connected clients")


if __name__ == "__main__":
    server = NFCGateServer((HOST, PORT), NFCGateClientHandler)
    server.serve_forever()
