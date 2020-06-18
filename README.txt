# prerequisites

sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.5-dev python3.5-venv libnfnetlink-dev libnetfilter-queue-dev sqlite3
sqlite3 xwd.db < ./sql/xdw.sql
python3.5 -m venv venv
. ./venv/bin/activate
pip3 install -r requirements.txt

# run as root

iptables -A INPUT -j NFQUEUE --queue-num 1
source venv/bin/activate
python main.py

