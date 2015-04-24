sudo iptables -I INPUT -d 192.168.1.1/24 -j NFQUEUE --queue-num 1
