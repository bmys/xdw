from scapy.layers.inet import IP, UDP, TCP, ICMP, TCP_SERVICES, Packet, Ether
from analyzers.Packet.packet_analyzer import PacketAnalyzer
from itertools import count
from utils import get_local_ip


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

        return data


class ScapyFlatAnalyzer(PacketAnalyzer):
    TCP_REVERSE = dict((TCP_SERVICES[k], k) for k in TCP_SERVICES.keys())

    class Extractor:
        def __init__(self, values):
            self.to_extract = list()

            for layer in values:
                l = (set(), set(), set())
                for value in layer:
                    if isinstance(value, tuple):
                        if isinstance(value[0], tuple):
                            l[2].add(value)
                        else:
                            l[1].add(value)
                    else:
                        l[0].add(value)
                self.to_extract.append(l)

        def extract(self, pkt: Packet):
            data = dict()
            for num, to_extract in enumerate(self.to_extract):
                layer = pkt.getlayer(num)

                for var_name in to_extract[0]:
                    data[var_name] = layer.__getattr__(var_name)

                for var_name in to_extract[1]:
                    data[var_name[1]] = layer.__getattr__(var_name[0])

                for var_name in to_extract[2]:
                    names, key = var_name

                    for name in names:
                        try:
                            data[key] = layer.__getattr__(name)

                            break
                        except AttributeError:
                            continue

            return data

    def __init__(self, values):
        # ('A', 'B', ('C', 'I_C')), ('D', 'C'), ('D', 'C')
        self.extractor = self.Extractor(values)

    def analyze_packet(self, pkt: bytes):
        pkt = IP(pkt)
        return self.extractor.extract(pkt)


class ScapyBasicAnalyzer(PacketAnalyzer):
    TCP_REVERSE = dict((TCP_SERVICES[k], k) for k in TCP_SERVICES.keys())
    LOCAL_IPS = get_local_ip()

    def analyze_packet(self, pkt: bytes):
        data = dict()
        pkt = IP(pkt)
        ip_layer = pkt.getlayer(0)

        # Features assignment
        data['direction'] = 'OUT' if ip_layer.src in self.LOCAL_IPS else 'IN'
        data['IP_len'] = ip_layer.len
        data['ttl'] = ip_layer.ttl

        second_layer = pkt.getlayer(1)
        data['service'] = self.TCP_REVERSE.get(second_layer.dport, 'unknown')
        data['protocol'] = second_layer.name

        return data

