# run as root
iptables -A INPUT -j NFQUEUE --queue-num 1
source venv/bin/activate
python main.py

