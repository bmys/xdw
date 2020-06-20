from datetime import datetime

from scapy.layers.inet import IP, UDP, TCP, ICMP, TCP_SERVICES, Packet
from analyzers.Frequency.frequency_analyzer import FrequencyAnalyzer
from analyzers.Packet.packet_analyzer import PacketAnalyzer
from itertools import count
from utils import get_local_ip, SuspicionModel, Suspicion
from sklearn.neighbors import KNeighborsClassifier
from joblib import load

model = load('notebooks/knn.joblib')
model_db = SuspicionModel.from_file("xwd.db")

def scale_data(a, means, var):
    return (a-means) / (var ** 0.5)


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

    freq = FrequencyAnalyzer(60, 1000)
    dos_dump = list()

    added = set()

    def analyze_packet(self, pkt: bytes):
        data = dict()
        pkt = IP(pkt)
        ip_layer = pkt.getlayer(0)
        # pkt.show2()
        # Features assignment
        # data['direction'] = 'OUT' if ip_layer.src in self.LOCAL_IPS else 'IN'
        data['IP_len'] = scale_data(ip_layer.len, means=548, var=459352)
        # data['ttl'] = ip_layer.ttl

        second_layer = pkt.getlayer(1)
        # second_layer.show2()
        # data['service'] = self.TCP_REVERSE.get(second_layer.sport, 'unknown')
        # data['protocol'] = second_layer.name
        data['len2'] = scale_data(len(second_layer), means=528, var=459352)
        data['frequency'] = scale_data(self.freq(ip_layer.src), means=2076, var=2569176)

        value = model.predict([[data['IP_len'], data['frequency'], data['len2']]])
        print(value, end=' ')
        print(ip_layer.src)
        # data['port_open'] = second_layer.sport

        if value[0] == 'dos':
            if ip_layer.src not in self.added:
                self.added.add(ip_layer.src)
                suspicion = Suspicion.insertable('dos', datetime.now().isoformat(), ip_layer.src, second_layer.name)
                model_db.create(suspicion)
                print('*' * 30)
                print('ADD NEW CASE')
                print('*' * 30)


        # self.dos_dump.append(data)

        # if ip_layer.src == '8.8.8.8' and data['frequency'] > 1650:
        #     self.dos_dump.append(data)

        return data

