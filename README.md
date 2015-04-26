#Arachnid

##Installing Dependencies
You are going to need to install all of the dependencies. Thankfully, I made a script that does it (yay for automation!):
	sudo sh install.sh

##Script Configuration
Next, take a look at the config.cfg file. It contains all of the parameters that you may want control over. Change them however you'd like.
If you are configuring a router, set the "mode" to *router*.
If you are configuring a host, set the "mode" to *host*

##Setup
On all nodes in the network, you need to set the routing tables for each of the nodes on the network. I did it the following way:
*(although there are a lot of other ways to accomplish the same thing and I'll probably change this when I find out how to do it better)*:

	`route add -host 192.168.1.104 gw 192.168.1.116`

*Again, change the IPs to match the ones on your network.*
This command, in other words, will make an entry in the routing table that will make all traffic destined for 192.168.1.104 pass through the specified gateway host, 192.168.1.116 (which on our network is a router). 

Verify that everything worked:

	`ip route show`
	`netstat -nr`

###Router Setup
**In the config file, set the "mode" parameter to *router***
####Disabling ICMP Redirects
Your Routers need to have ICMP redirects disabled. We do this because we don't want our routers accepting or sending out routes to other nodes on the network. Instead, we just want to use the static routes we set above. Issue the following command to disable both the sending and accepting of ICMP redirects:

	`echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/send_redirects`
	
	`echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/accept_redirects`

Issue this on all routers, legacy routers included.

####IPV4 Forwarding
You'll notice that nothing works if you are trying to route network through a router that has not enabled IPV4 Forwarding. So you'll want to do that too:

	`sudo sysctl -w net.ipv4.ip_forward=1`
Issue this on all routers, legacy routers included.

####IP Table Configuration
You need to set your IP tables rules to let Netfilter Queue intercept your packets. On your router nodes, you will want to issue the following command:

	`sudo iptables -I FORWARD -d 192.168.1.0/24 -j NFQUEUE --queue-num 1`

*Obviously, you will need to adjust the IP parameter to match the subnet of the network you are in.*
Do this just on routers that are running the AITF program. There's really no need to intercept packets on legacy routers.

###Host setup
**In the config file, set the "mode" parameter to *host***

####IP Table Configuration
You need to set your IP tables rules to let Netfilter Queue intercept your packets. On your router nodes, you will want to issue the following command:

	`sudo iptables -I INPUT -d 192.168.1.0/24 -j NFQUEUE --queue-num 1`

*Obviously, you will need to adjust the IP parameter to match the subnet of the network you are in.*

We use the **"INPUT"** chain here because we are really only interested in packets that are inbound to our interface. We used the **"FORWARD"** chain when configuring routers since we wanted to intercept packets that weren't sent for our router but were still passing through.








