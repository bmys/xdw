from Analyzers.Packet.ScapyPacketAnalyzer import ScapyAnalyzer
from Sensors.Packet.PacketSensor import NQPacketSensor

sensor = NQPacketSensor(packet_analyzer=ScapyAnalyzer())
sensor.run()
