from abc import ABC, abstractmethod


class PacketAnalyzer(ABC):
    @abstractmethod
    def analyze_packet(self, pkt: bytes):
        pass

