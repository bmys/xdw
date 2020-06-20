# Prerequisites

```sh
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.5-dev python3.5-venv libnfnetlink-dev libnetfilter-queue-dev sqlite3
sqlite3 xwd.db < ./sql/xdw.sql
python3.5 -m venv venv
. ./venv/bin/activate
pip3 install -r requirements.txt
```


# Queue
(as root)

```sh
iptables -A INPUT -j NFQUEUE --queue-num 1
source venv/bin/activate
python main.py
```

# CLI
## List all unhandled suspicions:
`python cli.py suspicions`

## Create rule:

(as root):

`python cli.py create-rule <SUSPICION-ID>`
