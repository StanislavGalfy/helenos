inet create-addr 1.0.0.1/8 net/eth1 a1
inet create-addr 2.0.0.1/8 net/eth2 a2
inet create-addr 10.10.10.1/24 net/eth3 a3
inet create-addr 10.10.20.1/24 net/eth4 a4
bird -d -c birdA.conf
