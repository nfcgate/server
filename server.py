#!/usr/bin/env python3

import socketserver
import struct
import sys

HOST = "0.0.0.0"
PORT = 5566


class PluginHandler:
    def __init__(self):
        self.plugin_list = []

        for modname in sys.argv[1:]:
            self.plugin_list.append(__import__("plugins.mod_%s" % modname, fromlist=["plugins"]))
            print("Loaded", "mod_%s" % modname)

    def filter(self, data):
        for plugin in self.plugin_list:
            data = plugin.handle_data(data)

        return data


class NFCGateClientHandler(socketserver.StreamRequestHandler):
    def __init__(self, request, client_address, srv):
        super().__init__(request, client_address, srv)
        self.session = None

    def setup(self):
        super().setup()

        self.session = None
        self.request.settimeout(60)
        print(self.client_address, "connected")

    def handle(self):
        super().handle()

        while True:
            msg_len_data = self.rfile.read(5)
            if len(msg_len_data) < 5:
                break

            msg_len, session = struct.unpack("!IB", msg_len_data)
            data = self.rfile.read(msg_len)
            print(self.client_address, "data:", bytes(data))

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
            self.server.send_to_clients(self.session, self.server.plugins.filter(data), self)

    def finish(self):
        super().finish()

        self.server.remove_client(self, self.session)
        print(self.client_address, "disconnected")


class NFCGateServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, request_handler, bind_and_activate=True):
        self.allow_reuse_address = True
        super().__init__(server_address, request_handler, bind_and_activate)

        self.clients = {}
        self.plugins = PluginHandler()
        print("NFCGate server listening on", server_address)

    def add_client(self, client, session):
        if session is None:
            return

        if session not in self.clients:
            self.clients[session] = []

        self.clients[session].append(client)
        print(client.client_address, "joined session", session)

    def remove_client(self, client, session):
        if session is None or session not in self.clients:
            return

        self.clients[session].remove(client)
        print(client.client_address, "left session", session)

    def send_to_clients(self, session, msg, origin):
        if session is None or session not in self.clients:
            return

        for client in self.clients[session]:
            # do not send message back to originator
            if client is origin:
                continue

            client.wfile.write(int.to_bytes(len(msg), 4, byteorder='big'))
            client.wfile.write(msg)

        print("Publish reached", len(self.clients[session]) - 1, "clients")


if __name__ == "__main__":
    server = NFCGateServer((HOST, PORT), NFCGateClientHandler)
    server.serve_forever()
