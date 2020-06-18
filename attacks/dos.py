from scapy.all import *
from scapy.layers.inet import IP, TCP


try:
    while True:
        pkt = IP(src='8.8.8.8', dst='127.0.1.1', ttl=21) / TCP(sport=45, dport=80)
        send(pkt, inter=.001)

        # p = IP(dst='127.0.0.1', id=1111, ttl=99) / TCP(sport=RandShort(), dport=[80], seq=666, ack=777, window=1234,
        #                                        flags="S") / "dos"
        # ans, unans = srloop(p, inter=0.3, retry=2, timeout=4)
        #
        # ans.summary()
        # unans.summary()

except KeyboardInterrupt:
    print('bye bye')
