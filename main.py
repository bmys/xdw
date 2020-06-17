from analyzers.Packet import ScapyAnalyzer
from analyzers.Packet.scapy_analyzer import ScapyFlatAnalyzer
from sensors.Packet import NFQSensor
from utils import PacketPipe, flatten, print_and_pass, get_local_ip

print(get_local_ip())

analyzer = ScapyFlatAnalyzer(
    (
         (
             ('len', 'len_1'),

         ),
         (
            (('len', 'window'), 'len_2'),
         )
    )
)

preprocessing = PacketPipe(analyzer, print_and_pass)
sensor = NFQSensor(packet_analyzer=preprocessing)
sensor.run()
