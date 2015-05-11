#!/usr/bin/env python 

import socket, struct

from sys import stdout
from os import urandom

from messages.c2c_pb2 import NFCData, Status
from messages.c2s_pb2 import Session, Data
from messages.metaMessage_pb2 import Wrapper

def printMsg(msg):
    assert len(msg) <= 74
    print msg, " "*(74-len(msg)),

def getSocket():
    tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tsock.connect(("127.0.0.1", 5566))
    return tsock


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
    try:
        lengthbuf = SocketReadN(sock, 4)
        length = struct.unpack(">i", lengthbuf)[0]
        wrapper = Wrapper()
        wrapper.ParseFromString(SocketReadN(sock, length))
        return wrapper
    except:
        return None

def sendOneMsg(msg, sock):
    mm = msg.SerializeToString()
    sock.sendall(struct.pack(">i", len(mm)) + mm)

def transceive(msg, sock):
    sendOneMsg(msg, sock)
    return RecvOneMsg(sock)

def getStatusMessage():
    data = Data()
    data.errcode = Data.ERROR_NOERROR
    status = Status()
    status.code = Status.CARD_FOUND
    iWrapper = Wrapper()
    iWrapper.Status.MergeFrom(status)
    data.blob = iWrapper.SerializeToString()
    wrapper = Wrapper()
    wrapper.Data.MergeFrom(data)
    return wrapper

def getSessionMessage(opcode, errcode=Session.ERROR_NOERROR, secret=None):
    session = Session()
    session.opcode = opcode
    session.errcode = errcode
    if secret is not None:
        session.session_secret = secret
    wrapper = Wrapper()
    wrapper.Session.MergeFrom(session)
    return wrapper

def getDummyDataMessage():
    data = Data()
    data.errcode = Data.ERROR_NOERROR
    nfcdata = NFCData()
    nfcdata.data_source = NFCData.CARD
    nfcdata.data_bytes = urandom(8)
    iWrapper = Wrapper()
    iWrapper.NFCData.MergeFrom(nfcdata)
    data.blob = iWrapper.SerializeToString()
    wrapper = Wrapper()
    wrapper.Data.MergeFrom(data)
    return wrapper

def assertSessionMessageState(msg, opcode, errcode=Session.ERROR_NOERROR):
    assert msg.WhichOneof('message') == 'Session'
    assert msg.Session.opcode == opcode
    assert msg.Session.errcode == errcode

def assertDataMessageState(msg, errcode=Data.ERROR_NOERROR, blob=None):
    assert msg.WhichOneof('message') == 'Data'
    assert msg.Data.errcode == errcode
    if blob is not None:
        assert msg.Data.blob == blob


### Session tests
sock = getSocket()
printMsg('Testing session creation...')
msg = getSessionMessage(Session.SESSION_CREATE)
reply = transceive(msg, sock)
assertSessionMessageState(reply, Session.SESSION_CREATE_SUCCESS)
assert reply.Session.session_secret != ""
secret = reply.Session.session_secret
print '[OK]'
# State: sock1 in Session 1

printMsg('Testing illegal creation of second session...')
msg = getSessionMessage(Session.SESSION_CREATE)
reply = transceive(msg, sock)
assertSessionMessageState(reply, Session.SESSION_CREATE_FAIL, Session.ERROR_CREATE_ALREADY_HAS_SESSION)
print '[OK]'
# State: sock1 in Session 1

sock4 = getSocket()
printMsg('Testing legal creation of second session')
msg = getSessionMessage(Session.SESSION_CREATE)
reply = transceive(msg, sock4)
assertSessionMessageState(reply, Session.SESSION_CREATE_SUCCESS)
assert reply.Session.session_secret != ""
secret2 = reply.Session.session_secret
print '[OK]'
# State: sock1 in Session 1, sock4 in Session2

sock2 = getSocket()
printMsg('Testing session join...')
msg = getSessionMessage(Session.SESSION_JOIN, secret=secret)
reply = transceive(msg, sock2)
assertSessionMessageState(reply, Session.SESSION_JOIN_SUCCESS)
notify = RecvOneMsg(sock)
assertSessionMessageState(notify, Session.SESSION_PEER_JOINED)
print '[OK]'
# State: sock1 and sock2 in Session 1, sock4 in Session 2

printMsg('Testing illegal second session join...')
msg = getSessionMessage(Session.SESSION_JOIN, secret=secret2)
reply = transceive(msg, sock2)
assertSessionMessageState(reply, Session.SESSION_JOIN_FAIL, Session.ERROR_JOIN_ALREADY_HAS_SESSION)
print '[OK]'
# State: sock1 and sock2 in Session 1, sock4 in Session 2

sock3 = getSocket()
printMsg('Testing join on full session...')
msg = getSessionMessage(Session.SESSION_JOIN, secret=secret)
reply = transceive(msg, sock3)
assertSessionMessageState(reply, Session.SESSION_JOIN_FAIL, Session.ERROR_JOIN_SESSION_FULL)
print '[OK]'
# State: sock1 and sock2 in Session 1, sock4 in Session 2

printMsg('Testing legal second session join...')
msg = getSessionMessage(Session.SESSION_JOIN, secret=secret2)
reply = transceive(msg, sock3)
assertSessionMessageState(reply, Session.SESSION_JOIN_SUCCESS)
notify = RecvOneMsg(sock4)
assertSessionMessageState(notify, Session.SESSION_PEER_JOINED)
print '[OK]'
# State: sock1 and sock2 in Session 1, sock4 and sock3 in Session 2

printMsg('Testing message passing in session 1...')
msg = getDummyDataMessage()
reply = transceive(msg, sock)
assertDataMessageState(reply)
msgI = RecvOneMsg(sock2)
assertDataMessageState(msgI, blob=msg.Data.blob)
print '[OK]'

printMsg('Testing NFC Card found status message in Session 1...')
msg = getStatusMessage()
reply = transceive(msg, sock)
assertDataMessageState(reply)
msgI = RecvOneMsg(sock2)
assertDataMessageState(msgI, blob=msg.Data.blob)
print '[OK]'

printMsg('Testing message reply in session 1...')
msg = getDummyDataMessage()
reply = transceive(msg, sock2)
assertDataMessageState(reply)
msgI = RecvOneMsg(sock)
assertDataMessageState(msgI, blob=msg.Data.blob)
print '[OK]'

printMsg('Testing message passing in session 2...')
msg = getDummyDataMessage()
reply = transceive(msg, sock3)
assertDataMessageState(reply)
msgI = RecvOneMsg(sock4)
assertDataMessageState(msgI, blob=msg.Data.blob)
print '[OK]'

printMsg('Testing message reply in session 2...')
msg = getDummyDataMessage()
reply = transceive(msg, sock4)
assertDataMessageState(reply)
msgI = RecvOneMsg(sock3)
assertDataMessageState(msgI, blob=msg.Data.blob)
print '[OK]'

# TODO Interleaved send and receive
printMsg('Testing session leave...')
msg = getSessionMessage(Session.SESSION_LEAVE, secret=secret)
reply = transceive(msg, sock2)
assertSessionMessageState(reply, Session.SESSION_LEAVE_SUCCESS)
notify = RecvOneMsg(sock)
assertSessionMessageState(notify, Session.SESSION_PEER_LEFT)
print '[OK]'
# State: sock1 in Session 1, sock4 and sock3 in Session 2

printMsg('Testing session leave 2...')
msg = getSessionMessage(Session.SESSION_LEAVE, secret=secret2)
reply = transceive(msg, sock3)
assertSessionMessageState(reply, Session.SESSION_LEAVE_SUCCESS)
notify = RecvOneMsg(sock4)
assertSessionMessageState(notify, Session.SESSION_PEER_LEFT)
print '[OK]'
# State: sock1 in Session1, sock4 in Session 2

printMsg('Testing join of recently vacated session...')
msg = getSessionMessage(Session.SESSION_JOIN, secret=secret)
reply = transceive(msg, sock3)
assertSessionMessageState(reply, Session.SESSION_JOIN_SUCCESS)
notify = RecvOneMsg(sock)
assertSessionMessageState(notify, Session.SESSION_PEER_JOINED)
print '[OK]'
# State: sock1 and sock3 in Session 1, sock4 in Session 2

printMsg('Testing session leave 3...')
msg = getSessionMessage(Session.SESSION_LEAVE, secret=secret)
reply = transceive(msg, sock)
assertSessionMessageState(reply, Session.SESSION_LEAVE_SUCCESS)
notify = RecvOneMsg(sock3)
assertSessionMessageState(notify, Session.SESSION_PEER_LEFT)
print '[OK]'
# State: sock3 in Session 1, sock4 in Session 2

printMsg('Testing session destruction 1...')
msg = getSessionMessage(Session.SESSION_LEAVE, secret=secret2)
reply = transceive(msg, sock4)
assertSessionMessageState(reply, Session.SESSION_LEAVE_SUCCESS)
print '[OK]'
# State: sock3 in Session 1, Session 2 destroyed

printMsg('Testing session destruction 2...')
msg = getSessionMessage(Session.SESSION_LEAVE, secret=secret)
reply = transceive(msg, sock3)
assertSessionMessageState(reply, Session.SESSION_LEAVE_SUCCESS)
print '[OK]'
# State: All Sessions destroyed

printMsg('Testing join on recently destroyed session...')
msg = getSessionMessage(Session.SESSION_JOIN, secret=secret)
reply = transceive(msg, sock)
assertSessionMessageState(reply, Session.SESSION_JOIN_FAIL, Session.ERROR_JOIN_UNKNOWN_SECRET)
print '[OK]'
# State: All Sessions destroyed
