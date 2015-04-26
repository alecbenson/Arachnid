echo "Starting setup..."
sudo apt-get install python-dev python-setuptools libnetfilter-queue-dev git
cd ../deps

cd dpkt-1.8
sudo python setup.py install
cd ../netifaces-0.10.4
sudo python setup.py install
cd ../pycrypto-2.6.1
sudo python setup.py install
cd ../python-netfilterqueue
sudo python setup.py install
cd ../scapy-2.3.1
sudo python setup.py install


cd ../../setup\ scripts
sudo sh nfqueue-iptable.sh
sudo python routing.py