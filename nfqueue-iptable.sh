sudo iptables -I INPUT -d 192.168.1.1/24 -j NFQUEUE --queue-num 1
sudo sysctl -w net.ipv4.ip_forward=1
