from analyzers.Packet import PacketAnalyzer


class Pipe:
    def __init__(self, *args):
        self.chain = list(args)

    def __call__(self, dt):
        val = dt
        for fun in self.chain:
            val = fun(val)
        return val


class PacketPipe(PacketAnalyzer):

    def __init__(self, packet_analyzer, *args):
        self.packet_analyzer = packet_analyzer
        self.pipe = Pipe(*args)
        self.packet = None

    def analyze_packet(self, pkt: bytes):
        self.packet = self.packet_analyzer.analyze_packet(pkt)
        return self.pipe(self.packet)
