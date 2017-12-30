inet create 1.0.0.1/24 net/eth1 a1
inet create 2.0.0.1/24 net/eth2 a2
inet create 10.10.10.1/24 net/eth3 a3
inet create 10.10.20.1/24 net/eth4 a4

inet add-sr 10.10.10.0/24 10.10.10.1 r3
inet add-sr 10.10.20.0/24 10.10.20.1 r4

logset debug2
bird -d -c rip-bird.conf