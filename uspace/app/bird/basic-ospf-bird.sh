inet create-addr 1.0.0.1/24 net/eth1 a1
inet create-addr 10.10.10.1/24 net/eth2 a2
logset debug2
bird -d -c ospf-bird.conf