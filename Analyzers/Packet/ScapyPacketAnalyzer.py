from scapy.layers.inet import IP, UDP, TCP, ICMP, TCP_SERVICES, Packet, Ether
from Analyzers.Packet.PacketAnalyzer import PacketAnalyzer
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

        # extract_packet_dump(pkt.show(dump=True))



        # print('PORT: ', pkt.dport)
        # print('src: ', pkt.src)

        # print('service name: ', self.TCP_REVERSE.get(pkt.dport, 'UNKNOWN'))
        # values = pkt.show(dump=True)
        # print(values)


# def extract_packet_dump(packet_info: str) -> dict:
#     data = dict()
#     prefix = ''
#     print(packet_info)
#     for line in packet_info.splitlines():
#         if line.startswith('###['):
#             _, packet_type, _ = line.split()
#             prefix = packet_type
#             # print('packet type: ', packet_type)
#
#     return data