# -*- mode: ruby -*-
# vi: set ft=ruby :

$routes1 = <<SCRIPT
  sudo route add -host 10.4.4.3 gw 10.4.4.2
  sudo route add -host 10.4.4.4 gw 10.4.4.2

  git clone https://github.com/fqrouter/python-netfilterqueue.git
  cd python-netfilterqueue
  sudo python setup.py install
SCRIPT

$routes2 = <<SCRIPT
  sudo route add -host 10.4.4.4 gw 10.4.4.3

  git clone https://github.com/fqrouter/python-netfilterqueue.git
  cd python-netfilterqueue
  sudo python setup.py install
SCRIPT

$routes3 = <<SCRIPT
  sudo route add -host 10.4.4.1 gw 10.4.4.2

  git clone https://github.com/fqrouter/python-netfilterqueue.git
  cd python-netfilterqueue
  sudo python setup.py install
SCRIPT

$routes4 = <<SCRIPT
  sudo route add -host 10.4.4.2 gw 10.4.4.3
  sudo route add -host 10.4.4.1 gw 10.4.4.3

  git clone https://github.com/fqrouter/python-netfilterqueue.git
  cd python-netfilterqueue
  sudo python setup.py install
SCRIPT

Vagrant.configure(2) do |config|
  config.vm.provision :shell, path: "deps.sh"

  config.vm.define "aitf1" do |aitf1|
    aitf1.vm.box = "hashicorp/precise32"
    aitf1.vm.network "private_network", ip: "10.4.4.1"
    aitf1.vm.provision :shell, :inline => $routes1
  end

  config.vm.define "aitf2" do |aitf2|
    aitf2.vm.box = "hashicorp/precise32"
    aitf2.vm.network "private_network", ip: "10.4.4.2"
    aitf2.vm.provision :shell, :inline => $routes2
  end

  config.vm.define "aitf3" do |aitf3|
    aitf3.vm.box = "hashicorp/precise32"
    aitf3.vm.network "private_network", ip: "10.4.4.3"
    aitf3.vm.provision :shell, :inline => $routes3
  end

  config.vm.define "aitf4" do |aitf4|
    aitf4.vm.box = "hashicorp/precise32"
    aitf4.vm.network "private_network", ip: "10.4.4.4"
    aitf4.vm.provision :shell, :inline => $routes4
  end
end