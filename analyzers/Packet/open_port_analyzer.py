from utils.open_ports import open_ports


class OpenPortAnalyzer:
    def __init__(self, seconds, hits):
        self.seconds = seconds
        self.hits = hits
        self.open_ports = open_ports()

    def __call__(self, data):
        self.open_ports = open_ports()
        data['port_open'] = True if (data['port_open'] in self.open_ports
                                     or data['direction'] == 'OUT') else False
        return data
