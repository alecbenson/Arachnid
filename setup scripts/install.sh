echo "Installing dependencies..."
sudo apt-get install python-pip build-essential python-dev libnetfilter-queue-dev python-setuptools
sudo pip install scapy
sudo pip install pycrypto
sudo pip install netifaces

cd ~/Desktop
echo "Cloning netfilterqueue repo..."
git clone https://github.com/fqrouter/python-netfilterqueue.git
echo "Downloading dpkt..."
wget https://dpkt.googlecode.com/files/dpkt-1.8.tar.gz
echo "Extracting dpkt..."
tar -xf dpkt-1.8.tar.gz
cd dpkt-1.8
echo "Installing dpkt..."
sudo python setup.py install

Echo "installing netfilterqueue..."
cd ..
cd python-netfilterqueue

sudo python setup.py install

echo "Done!"
