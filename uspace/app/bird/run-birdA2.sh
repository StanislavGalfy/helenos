inet create-addr 10.10.20.2/24 net/eth1 a1
inet create-addr 10.10.30.2/24 net/eth2 a2
inet create-addr 10.10.50.1/24 net/eth3 a3
bird -d -c birdA2.conf
