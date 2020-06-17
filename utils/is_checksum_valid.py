from scapy.layers.inet import IP
from scapy.packet import Packet


def is_checksum_valid(pkt: Packet):
    raise NotImplementedError
    # original = pkt['TCP'].chksum
    # del pkt['TCP'].chksum
    # packet = IP(str(pkt))
    # new = packet['TCP'].chksum