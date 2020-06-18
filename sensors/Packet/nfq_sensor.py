from netfilterqueue import NetfilterQueue, Packet
from analyzers.Packet import PacketAnalyzer
import json


class NFQSensor:
    def __init__(self, packet_analyzer: PacketAnalyzer):
        self.packet_analyzer = packet_analyzer
        self.nfqueue = NetfilterQueue()
        self.nfqueue.bind(1, self.get_bytes_and_accept)

    def get_bytes_and_accept(self, pkt: Packet):
        payload = pkt.get_payload()
        self.packet_analyzer.analyze_packet(payload)
        pkt.accept()

    def run(self):
        try:
            self.nfqueue.run()
        except KeyboardInterrupt:
            # with open('./normal.json', 'w') as fout:
            #     json.dump(self.packet_analyzer.dos_dump, fout)
            pass
