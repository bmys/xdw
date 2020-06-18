from analyzers.Packet import ScapyAnalyzer
from analyzers.Packet.open_port_analyzer import OpenPortAnalyzer
from analyzers.Packet.scapy_analyzer import ScapyFlatAnalyzer, ScapyBasicAnalyzer
from sensors.Packet import NFQSensor
from utils import PacketPipe, print_and_pass, get_local_ip
from utils.open_ports import open_ports

print(get_local_ip())
print(open_ports())
# analyzer = ScapyFlatAnalyzer(
#     (
#          (
#              ('len', 'len_1'),
#
#          ),
#          (
#             (('len', 'window'), 'len_2'),
#          )
#     )
# )

analyzer = ScapyBasicAnalyzer()
# OpenPortAnalyzer(60, 20)

preprocessing = PacketPipe(analyzer, print_and_pass)
sensor = NFQSensor(packet_analyzer=analyzer)
sensor.run()
