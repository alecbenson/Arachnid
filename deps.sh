#!/usr/bin/env bash
apt-get update
apt-get -y install vim traceroute git python python-dev python-setuptools python-pip libnetfilter-queue-dev 
pip install scapy
pip install pycrypto
pip install netifaces
pip install dpkt
echo "echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/send_redirects" >> /home/vagrant/.bashrc
echo "echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/accept_redirects" >> /home/vagrant/.bashrc
echo "sudo iptables -X" >> /home/vagrant/.bashrc
echo "sudo iptables -F" >> /home/vagrant/.bashrc
echo "sudo sysctl -w net.ipv4.ip_forward=1" >> /home/vagrant/.bashrc
echo "cd /vagrant/" >> /home/vagrant/.bashrc
echo "sudo netstat -nr" >> /home/vagrant/.bashrc

