from analyzers.Packet import ScapyAnalyzer
from sensors.Packet import NFQSensor

sensor = NFQSensor(packet_analyzer=ScapyAnalyzer())
sensor.run()
