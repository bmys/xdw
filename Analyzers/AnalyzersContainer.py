from dependency_injector import containers, providers
import Analyzers.Packet.ScapyPacketAnalyzer


class AnalyzersContainer(containers.DeclarativeContainer):
    scapy = providers.Factory()