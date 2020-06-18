import psutil


def open_ports():
    conns = psutil.net_connections('inet')
    return [c.laddr[1] for c in conns]
