inet create-addr 2.0.0.2/8 net/eth1 a1
inet create-addr 3.0.0.2/8 net/eth2 a1
inet create-addr 30.10.10.1/24 net/eth3 a2
inet create-addr 30.10.20.1/24 net/eth4 a3
bird -d -c birdC.conf
