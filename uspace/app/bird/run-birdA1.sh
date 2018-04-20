inet create-addr 10.10.10.2/24 net/eth1 a1
inet create-addr 10.10.30.1/24 net/eth2 a2
inet create-addr 10.10.40.1/24 net/eth3 a3
logset fatal
bird -d -c birdA1.conf
