from scapy.layers.inet import IP, UDP, TCP, ICMP, TCP_SERVICES, Packet, Ether
from analyzers.Packet.packet_analyzer import PacketAnalyzer
from itertools import count
import pprint

pp = pprint.PrettyPrinter(indent=4)


class ScapyAnalyzer(PacketAnalyzer):
    TCP_REVERSE = dict((TCP_SERVICES[k], k) for k in TCP_SERVICES.keys())

    def analyze_packet(self, pkt: bytes):
        data = dict()
        pkt = IP(pkt)

        for i in count(0):
            layer = pkt.getlayer(i)
            if layer is None:
                break
            data[layer.name] = layer.fields

        pp.pprint(data)
        print('\n'*5)
