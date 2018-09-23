from plugins.c2c_pb2 import NFCData
from plugins.c2s_pb2 import ServerData


def format_data(data):
    if len(data) == 0:
        return ""

    nfc_data = NFCData()
    nfc_data.ParseFromString(data)

    letter = "C" if nfc_data.data_source == NFCData.CARD else "R"
    initial = "(initial) " if nfc_data.data_type == NFCData.INITIAL else ""
    return "%s: %s%s" % (letter, initial, bytes(nfc_data.data))


def handle_data(data):
    server_message = ServerData()
    server_message.ParseFromString(data)

    print("[log]", ServerData.Opcode.Name(server_message.opcode), format_data(server_message.data))
    return data
