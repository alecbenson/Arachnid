echo Installing scapy & netfilterqueue
sudo apt-get install python-pip build-essential python-dev libnetfilter-queue-dev
sudo pip install scapy
cd ~/Desktop
git clone https://github.com/fqrouter/python-netfilterqueue.git
cd python-netfilterqueue
sudo python setup.py install
echo fuck yeh
