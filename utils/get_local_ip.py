import socket


def get_local_ip():
    local_1 = socket.gethostbyname(socket.gethostname())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_2 = s.getsockname()[0]
    s.close()
    return local_1, local_2
