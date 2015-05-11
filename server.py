#!/usr/bin/env python 

import socket, select, struct
from random import randint

from messages import c2c_pb2
from messages import c2s_pb2
from messages import metaMessage_pb2

HOST = "0.0.0.0"
PORT = 5566

SESSIONS = {}
PAIRS = {}
LIMBO = []

STATUS_CODES = {
    c2c_pb2.Status.KEEPALIVE_REQ   : "Keepalive request",
    c2c_pb2.Status.KEEPALIVE_REP   : "Keepalive response",
    c2c_pb2.Status.CARD_FOUND      : "Card found",
    c2c_pb2.Status.CARD_REMOVED    : "Card removed",
    c2c_pb2.Status.READER_FOUND    : "Reader found",
    c2c_pb2.Status.READER_REMOVED  : "Reader removed",
    c2c_pb2.Status.NFC_NO_CONN     : "NFC connection lost",
    c2c_pb2.Status.INVALID_MSG_FMT : "Invalid message format",
    c2c_pb2.Status.NOT_IMPLEMENTED : "Not implemented",
    c2c_pb2.Status.UNKNOWN_MESSAGE : "Unknown Message",
    c2c_pb2.Status.UNKNOWN_ERROR   : "Unknown Error"
}

NFC_CODES = {
    c2c_pb2.NFCData.READER: "Reader",
    c2c_pb2.NFCData.CARD  : "Card"
}

### Dirty hack class
class pseudoSocket():
    def getpeername(self):
        return "[no peer]"

### Network helper functions
def SocketReadN(sock, n):
    buf = b''
    while n > 0:
        data = sock.recv(n)
        if data == b'':
            raise RuntimeError('unexpected connection close')
        buf += data
        n -= len(data)
    return buf


def RecvOneMsg(sock):
    lengthbuf = SocketReadN(sock, 4)
    length = struct.unpack('>i', lengthbuf)[0]
    wrapper = metaMessage_pb2.Wrapper()
    wrapper.ParseFromString(SocketReadN(sock, length))
    return wrapper


def sendMessage(msg, sock):
    ms = msg.SerializeToString()
    # mb = [elem.encode('hex') for elem in ms]
    sock.sendall(struct.pack(">i", len(ms)) + ms)


### Debugging helper functions
def prettyPrintProtobuf(msg, sock):
    peer = getPeerSocket(sock)
    if peer is None:
        peer = pseudoSocket()
    mtype = msg.WhichOneof('message')
    if mtype == "Status":
        mStatus = msg.Status
        print """{} => {}: Status
    StatusCode: {}""".format(
            sock.getpeername(),
            peer.getpeername(),
            STATUS_CODES[mStatus.code]
        )
    elif mtype == "Anticol":
        mAnticol = msg.Anticol
        print """{} => {}: Anticol
    UID:  {}
    Hist: {}
    ATQA: {}
    SAK:  {}""".format(
            sock.getpeername(),
            peer.getpeername(),
            ''.join(x.encode('hex') for x in mAnticol.UID),
            ''.join(x.encode('hex') for x in mAnticol.historical_byte),
            ''.join(x.encode('hex') for x in mAnticol.ATQA),
            ''.join(x.encode('hex') for x in mAnticol.SAK)
        )
    elif mtype == "NFCData":
        mNfc = msg.NFCData
        print """{} => {}: NFCData
    DataSource: {}
    data_bytes: {}""".format(
            sock.getpeername(),
            peer.getpeername(),
            NFC_CODES[mNfc.data_source],
            ''.join(x.encode('hex') for x in mNfc.data_bytes)
        )


##### Message Creation Functions
### Session Messages
def getSessionMessage(code_tuple):
    imsg = c2s_pb2.Session()
    imsg.opcode = code_tuple[0]
    imsg.errcode = code_tuple[1]
    msg = metaMessage_pb2.Wrapper()
    msg.Session.MergeFrom(imsg)
    return msg


def getSessionMessageWithSecret(secret):
    imsg = c2s_pb2.Session()
    imsg.opcode = c2s_pb2.Session.SESSION_CREATE_SUCCESS
    imsg.errcode = c2s_pb2.Session.ERROR_NOERROR
    imsg.session_secret = secret
    msg = metaMessage_pb2.Wrapper()
    msg.Session.MergeFrom(imsg)
    return msg


### Data Messages
def getDataMessage(errcode):
    imsg = c2s_pb2.Data()
    imsg.errcode = errcode
    msg = metaMessage_pb2.Wrapper()
    msg.Data.MergeFrom(imsg)
    return msg


def getDataMessageWithBlob(blob):
    imsg = c2s_pb2.Data()
    imsg.errcode = c2s_pb2.Data.ERROR_NOERROR
    imsg.blob = blob
    msg = metaMessage_pb2.Wrapper()
    msg.Data.MergeFrom(imsg)
    return msg


##### Helper functions
### Session Management
def getPeerSocket(sock):
    try:
        return PAIRS[sock]
    except KeyError:
        return None


def NewSession(sock):
    if sock not in PAIRS and sock not in LIMBO:
        secret = str(randint(100000,999999))
        while secret in SESSIONS.keys():
            secret = randint(100000,999999)
        SESSIONS[secret] = [sock]
        LIMBO.append(sock)
        print "Created session", secret
        return secret
    else:
        print "Attempt to create a session while in limbo for other session",
        return ""


def JoinSession(secret, sock):
    try:
        if sock not in PAIRS and sock not in LIMBO:
            if len(SESSIONS[secret]) == 1:
                peer = SESSIONS[secret][0]
                PAIRS[peer] = sock
                PAIRS[sock] = peer
                LIMBO.remove(peer)
                NotifySessionStatus(c2s_pb2.Session.SESSION_PEER_JOINED, peer)
                SESSIONS[secret].append(sock)
                print "Client joined session", secret
                return (c2s_pb2.Session.SESSION_JOIN_SUCCESS, c2s_pb2.Session.ERROR_NOERROR)
            else:
                print "Attempt to join session {} failed, session full".format(secret)
                return (c2s_pb2.Session.SESSION_JOIN_FAIL, c2s_pb2.Session.ERROR_JOIN_SESSION_FULL)
        else:
            print "Attempted to join session while already part of other session"
            return (c2s_pb2.Session.SESSION_JOIN_FAIL, c2s_pb2.Session.ERROR_JOIN_ALREADY_HAS_SESSION)
    except KeyError:
        print "Attempt to join session {} failed, no such session".format(secret)
        return (c2s_pb2.Session.SESSION_JOIN_FAIL, c2s_pb2.Session.ERROR_JOIN_UNKNOWN_SECRET)


def LeaveSession(secret, sock):
    try:
        if sock in SESSIONS[secret]:
            SESSIONS[secret].remove(sock)
            if len(SESSIONS[secret]) >= 1:
                peer = SESSIONS[secret][0]
                del PAIRS[peer]
                del PAIRS[sock]
                LIMBO.append(peer)
                NotifySessionStatus(c2s_pb2.Session.SESSION_PEER_LEFT, peer)
                print "Client left session", secret
            else:
                del SESSIONS[secret]
                print "Client left session {}. Session empty, destroying it".format(secret)
            if sock in LIMBO:
                LIMBO.remove(sock)
            return (c2s_pb2.Session.SESSION_LEAVE_SUCCESS, c2s_pb2.Session.ERROR_NOERROR)
        else:
            print "Attempt to leave session {} failed, session was never joined".format(secret)
            return (c2s_pb2.Session.SESSION_LEAVE_FAIL, c2s_pb2.Session.ERROR_LEAVE_NOT_JOINED)
    except KeyError:
        print "Attemt to leave session {} failed, no such session".format(secret)
        return (c2s_pb2.Session.SESSION_LEAVE_FAIL, c2s_pb2.Session.ERROR_LEAVE_UNKNOWN_SECRET)


def NotifySessionStatus(status, sock):
    msg = getSessionMessage((status, c2s_pb2.Session.ERROR_NOERROR))
    sendMessage(msg, sock)


##### Handlers
def HandleNFCDataMessage(message, sock):
    print "Got NFCData message. This should not happen. Doing nothing"

def HandleStatusMessage(message, sock):
    print "Got Status message. This should not happen. Doing nothing."

def HandleAnticolMessage(message, sock):
    print "Got Anticol message. This should not happen. Doing nothing."

def HandleDataMessage(message, sock):
    errcode = None
    peer = getPeerSocket(sock)
    if peer is not None:
        try:
            print "Forwarding message"
            sendMessage(message, peer)
            print "Notifying sender"
            errcode = c2s_pb2.Data.ERROR_NOERROR
        except Exception, e:
            print "Error while trying to forward data message: ", e
            NotifySessionStatus(c2s_pb2.Session.SESSION_PEER_LEFT, sock)
            del PAIRS[sock]
            del PAIRS[peer]
            LIMBO.append(sock)
            errcode = c2s_pb2.Data.ERROR_TRANSMISSION_FAILED
    else:
        errcode = c2s_pb2.Data.ERROR_NO_SESSION
    wrapper = metaMessage_pb2.Wrapper()
    wrapper.ParseFromString(message.Data.blob)
    prettyPrintProtobuf(wrapper, sock)
    return getDataMessage(errcode)

def HandleSessionMessage(message, sock):
    if message.opcode == c2s_pb2.Session.SESSION_CREATE:
        secret = NewSession(sock)
        if secret != "":
            return getSessionMessageWithSecret(secret)
        else:
            return getSessionMessage((c2s_pb2.Session.SESSION_CREATE_FAIL, c2s_pb2.Session.ERROR_CREATE_ALREADY_HAS_SESSION))
    elif message.opcode == c2s_pb2.Session.SESSION_JOIN:
        return getSessionMessage(JoinSession(message.session_secret, sock))
    elif message.opcode == c2s_pb2.Session.SESSION_LEAVE:
        return getSessionMessage(LeaveSession(message.session_secret, sock))


def HandleMessage(message, sock):
    mtype = message.WhichOneof('message')
    if mtype == "Session":
        return HandleSessionMessage(message.Session, sock)
    elif mtype == "Data":
        return HandleDataMessage(message, sock)
    elif mtype == "NFCData":
        return HandleNFCDataMessage(message.NFCData, sock)
    elif mtype == "Status":
        return HandleStatusMessage(message.Status, sock)
    elif mtype == "Anticol":
        return HandleAnticolMessage(message.Anticol, sock)



##### Main code
if __name__ == "__main__":
     
    CONNECTION_LIST = []    # list of socket clients
    RECV_BUFFER = 4096 # Advisable to keep it as an exponent of 2
        
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Set TCP Nodelay (currently bugged, enable only for debugging)
    server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    server_socket.bind((HOST, PORT))
    server_socket.listen(10)

    # Add server socket to the list of readable connections
    CONNECTION_LIST.append(server_socket)

    print "NFCGate server started on port " + str(PORT)

    while 1:
        # Get the list sockets which are ready to be read through select
        read_sockets,write_sockets,error_sockets = select.select(CONNECTION_LIST,[],[])


        for sock in read_sockets:
            
            #New connection
            if sock == server_socket:
                # Handle the case in which there is a new connection recieved through server_socket
                sockfd, addr = server_socket.accept()

                sockfd.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                CONNECTION_LIST.append(sockfd)
                print "Client (%s, %s) connected" % addr
                
            #Some incoming message from a client
            else:
                # Data recieved from client, process it
                try:
                    #In Windows, sometimes when a TCP program closes abruptly,
                    # a "Connection reset by peer" exception will be thrown
                    wrapperMsg = RecvOneMsg(sock)
                    if wrapperMsg:
                        reply = HandleMessage(wrapperMsg, sock)
                        # w_reply = wrapMessage(reply)
                        sendMessage(reply, sock)

                # client disconnected, so remove from socket list
                except Exception, e:
                    # broadcast_data(sock, "Client (%s, %s) is offline" % addr)
                    print "Client (%s, %s) is offline" % addr
                    sock.close()
                    CONNECTION_LIST.remove(sock)
                    try:
                        peer = PAIRS[sock]
                        for secret in SESSIONS:
                            if sock in SESSIONS[secret]:
                                SESSIONS[secret].remove(sock)
                                break
                        del PAIRS[sock]
                        del PAIRS[peer]
                        LIMBO.append(peer)
                        NotifySessionStatus(c2s_pb2.Session.SESSION_PEER_LEFT, peer)
                    except KeyError:
                        pass
                    continue
        
    server_socket.close()
