inet create 1.0.0.1/24 net/eth1 a1
inet create 10.10.10.1/24 net/eth2 a2
inet add-sr 10.10.10.0/24 10.10.10.1 r1
logset debug2
bird -d -c rip-bird.conf
