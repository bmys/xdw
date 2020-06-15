from analyzers.Packet import ScapyAnalyzer
from sensors.Packet import NFQSensor
from utils import PacketPipe, flatten, print_and_pass

preprocessing = PacketPipe(ScapyAnalyzer, flatten, print_and_pass)
sensor = NFQSensor(packet_analyzer=preprocessing)
sensor.run()
