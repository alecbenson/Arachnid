sudo iptables -I FORWARD -d 10.4.4.1/8 -j NFQUEUE --queue-num 1
sudo sysctl -w net.ipv4.ip_forward=1
echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/send_redirects
echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/accept_redirects