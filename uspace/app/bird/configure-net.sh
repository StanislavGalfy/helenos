inet create 1.0.0.1/24 net/eth1 a1
inet create 10.10.10.1/24 net/eth2 a2
inet add-sr 10.20.10.0/24 1.0.0.2 r1
logset debug2
