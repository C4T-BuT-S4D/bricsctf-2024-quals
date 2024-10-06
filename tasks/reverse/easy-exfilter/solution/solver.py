import pyshark
from binascii import unhexlify

string = ''
shark_cap = pyshark.FileCapture('exfilter_traff.pcapng')
for packet in shark_cap:
    if packet.transport_layer != "UDP":
        continue

    try:
        val = int(packet.ip.dsfield, 16)
    except:
        val = 0

    if val != 0:
        data = ''.join(packet.udp.payload.split(':'))
        data = unhexlify(data)

        if data[val-1] == 0:
            print()
            continue
        string += chr(data[val-1])

print(string[::-1])

# c544dd9de4f7ec011c904795692db31e
# c544dd9de4f7ec011c904795692db31e