from scapy.all import *
from struct import *
from netfilterqueue import NetfilterQueue
from Crypto.Cipher import AES
from subprocess import call
import socket, sys, time, config, random
import binascii, threading, dpkt, atexit

'''This class is used to help determine the length of the RR field when decoding packets'''
class XFieldLenField(FieldLenField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))  

'''This class is used to represent the structure of an AITF shim'''
class AITF(Packet):
	name = "AITF"
	fields_desc = [BitField("PayloadProto", None, 8),
	XFieldLenField("length", None, length_of="RR", fmt="H"),
	StrLenField("RR", "", length_from=lambda x:x.length)]


'''The Packet class is responsible for intercepting and sending on modified traffic'''
class Transit():

	'''
	Binds IP layers for scapy.
	These bindings help us decide how to interpret the payload of the packet
	'''
	def bind_packet_layers(self):
		#AITF packets use IP proto #145 and can be identified this way
		bind_layers(IP, AITF, proto=145)
		bind_layers(AITF, TCP, PayloadProto=6)
		bind_layers(AITF, ICMP, PayloadProto=1)
		bind_layers(AITF, UDP, PayloadProto=17)


	'''Takes in a block request and processes it'''
	def manage_block_request(self, pkt, load, level):
		#1. Set a local filter and once it expires keep an entry in the shadow table
		#An entry is 8 characters long, so we use escalation index as 
		#an index multiplier to find the correct IP address and nonce to block
		escalation_index = 16*level

		#Agw is the attacker gateway. We can find it in this part of the RR
		agw_IP = self.hex_to_ip( load[ 24 + escalation_index : 32 + escalation_index ] )
		block_dest = load[ 8 + escalation_index : 16 + escalation_index ]
		block_path = load[8 : load.index(block_dest) + 16]

		#If we are the attacker's gateway (or the next gateway in the event of escalation)
		if pkt.dst == agw_IP:
			nonce = load[32 + escalation_index : 40 + escalation_index]
			if self.is_valid_nonce(agw_IP, nonce):
				#IP address of the attacker. We can find it in this part of the RR
				shadow_table[block_path] = time.time() + config_params.filter_duration
				print "Installed filter: blocking traffic from route {0}".format( str(block_path) )
			else:
				print "Did NOT install filter: attacker has spoofed this path".format(nonce)
		else:
			print "Forwarding the requst to the proper attacker gateway, {0}\n".format( agw_IP )
			shadow_table[block_path] = time.time() + config_params.temp_filter_duration
			self.three_way_handshake( config_params.local_ip, agw_IP, load)


	'''
	Initiates a three way handshake between source IP and destination IP with payload 'payload'
	'''
	def three_way_handshake(self, src, dst, payload):
				#Form the requst packet and shove the RR path in the payload
		sport = random.randint(1024,65535)
		seq= random.randint(1,1000000)

		#three way hannnndshakkeeeee!! (whaaat)
		ip = IP(src=src, dst=dst )
		tcp_syn = TCP(sport=sport, dport=80, flags='S', seq=seq)
		tcp_synack = sr1(ip/tcp_syn, verbose=0)

		#Respond with final ack!
		#Note that there is a slight complication here. 
		#Because of the way scapy works, the host is actually totally unaware that we are trying to open up a TCP connection.
		#When it gets the synack back, our own host freaks out and tries to reset the connection.
		#We can solve this by blocking outbound reset packets with an Ip table rule.
		tcp_ack = TCP(sport=sport, dport=80, flags='A', seq=tcp_synack.ack, ack=tcp_synack.seq + 1)
		send(ip/tcp_ack)

		#Send the payload over
		tcp_send = TCP(sport=sport, dport=80, flags="PA", seq=tcp_synack.ack, ack=tcp_synack.seq + 1)
		send(ip/tcp_send/payload)

	'''
	Probes the next hope for AITF support by sending a packet with TTL 1 and looking for code 2 in the response.
	We use code 2 because it is never used for Time Exceeded ICMP responses and we can use it to identify AITF enabled routers
	'''
	def forward_packet(self, pkt, packet):
		if pkt.dst in aitf_routers:
			#Remove AITF shims and send the packet on
			if aitf_routers[pkt.dst] == False:
				pkt = self.remove_AITF_shim(pkt)
			#Next hop is AITF enabled, add/Update AITF shim
			else:
				pkt = self.shim_packet(pkt)

			packet.set_payload( str(pkt) )
			packet.accept()
			return pkt

		pkt = self.remove_AITF_shim(pkt)
		packet.set_payload( str(pkt) )
		packet.accept()

		#There is no entry for this packet yet, send a probe out
		aitf_routers[pkt.dst] = False
		probe = IP(src=config_params.local_ip, dst=pkt.dst, ttl=1)/ICMP(code=4)
		send(probe)

	'''
	Processes AITF probes and determines if the router/host is legacy or AITF enabled
	Returns either the query packet we received, or the response packet of our probe
	'''
	def handle_AITF_probe(self, pkt, packet):
		if pkt.haslayer(ICMP):
			if pkt.haslayer(ICMPerror):
				#We were queried by another AITF enabled router, respond as AITF enabled
				if pkt.src == config_params.local_ip:
					pkt[ICMPerror].code = 2
					del pkt.chksum
					print "Responded to {0}'s AITF probe message\n".format( pkt.dst )
					packet.set_payload( str(pkt) )
					packet.accept()
					return True

				#We received the response of our previous query
				elif pkt.dst == config_params.local_ip:
					dst = pkt[IPerror].dst
					if pkt[ICMPerror].code == 2:
						aitf_routers[dst] = True
						print "{0} is an AITF enabled router\n".format( pkt.src )
						packet.accept()
						return True
					else:
						aitf_routers[dst] = False
						print "{0} is NOT an AITF enabled router\n".format( pkt.src )
						packet.accept()
						return True

			#Our probe didn't expire, the next hop is the destination
			elif pkt[ICMP].type == 0:
				if pkt[ICMP].code == 4:
					aitf_routers[pkt.src] = False
					packet.accept()
					return True
				elif pkt[ICMP].code == 2:
					aitf_routers[pkt.src] = True
					packet.accept()
					return True
		return False


	'''Called when the host receives a probe'''
	def handle_host_probe(self, pkt, packet):
		if pkt.haslayer(ICMP):
			if pkt[ICMP].type == 8:
				if pkt[ICMP].code == 4:
					pkt[ICMP].code = 2
					del pkt.chksum
					del pkt[ICMP].chksum
					print "Responded to {0}'s AITF probe message\n".format( pkt.src )
					packet.set_payload( str(pkt) )
					packet.accept()



	def check_block_table(self, pkt, packet):
		#Check to make sure the source isn't blocked
		path = ""
		if pkt.haslayer(AITF):
			path = pkt[AITF].RR
		else:
			path = self.ip_to_hex(pkt.src) + "ffffffff"
		
		if path not in shadow_table:
			return False

		time_left = shadow_table[path] - time.time()
		if time_left > 0:
			print "Dropping packet from blocked path. Still {1} seconds left in filter\n".format(path, time_left)
			packet.drop()
			return True
		return False




	def handle_block_request(self, pkt, packet):
			#If the packet is destined to the router, we are likely receiving a block reqeuest
			if pkt.dst == config_params.local_ip:
				if pkt.haslayer(TCP) and pkt.haslayer(Raw):
					load = str(pkt[Raw].load)
					if "RRBLOCK:" in load:
						escalation_index = int(load[-1:])
						self.manage_block_request(pkt, load, escalation_index)
						return True
			return False





	'''
	Callback function for NfQueue. 
	If the machine is in "host" mode, then it will check to see if it is receiving too much traffic.
	If the machine is in "router" mode, then it will shim packets
	'''
	def callback(self, packet):
		pkt = IP(packet.get_payload())
		if config_params.mode == "router":
			#Check to make sure the source isn't blocked
			if self.check_block_table(pkt, packet):
				return
			#Check if the packet is a probe, deal with it accordingly
			if self.handle_AITF_probe(pkt, packet):
				return
			#Check if the packet is a block request, deal with it accordingly
			if self.handle_block_request(pkt, packet):
				return
			#We check if the next hop is AITF enabled and shim packets if it is. Otherwise, remove the shim.
			self.forward_packet(pkt, packet)

		elif config_params.mode == "host":
			pkt.show()
			self.handle_host_probe(pkt, packet)
			self.check_traffic(pkt, packet)
			pkt = self.remove_AITF_shim(pkt)
			packet.set_payload( str(pkt) )
			packet.accept()
		else:
			print "Unrecognized mode set in the config: {0}\n".format(config_params.mode)
			sys.exit()


	'''
	Converts an IP to hex format for storing in the route record
	We need to encode this in hex because otherwise the character length of the IP may vary and then parsing the IP becomes a pain.
		(For instance, 130.215.250.122 is 15 characters while 8.8.8.8 is 7). In hex, they're all 8 characters long
	'''
	def ip_to_hex(self, ip):
		return binascii.hexlify(socket.inet_aton(ip))


	'''
	Converts a hex IP address back into the more familiar format
	'''
	def hex_to_ip(self, hex_ip):
		return socket.inet_ntoa( binascii.unhexlify(hex_ip) )


	'''
	Generates a hash of the given IPV4 address using the node's secret key

	The RR nonces work in the following way:
		1. The nonce is a hash of the packet's destination IP address and the node's private key.
		
		2. A block request includes the path that the filtering request issuer wants blocked.
		3. The node that processes the block request needs to ensure that it did in fact forward the packets that the victim wants blocked. 
		(Otherwise, an asshole could get legitimate traffic blocked by spoofing)

		4. The node verifies that it forwarded the packets by hashing the filtering request issuer's IP with 
		the node's secret key and making sure that the result matches the hash in step 1. 

		5. If it doesn't match, then it knows that traffic was spoofed and the node replies to the filtering request issuer with the correct hash in step 1.
		6. The block issuer can then use this information to filter out any traffic with the spoofed route (traffic that has the wrong nonce value)
	'''
	def hash_ip(self, ip):
		#We have to convert these to binary since the AES keys have to be multiples of 16 in length
		binary_ip = ''.join( '{:08b}'.format(int(x)) for x in ip.split('.') )

		encobj = AES.new(config_params.node_secret_key, AES.MODE_ECB)
		return encobj.encrypt(binary_ip).encode('hex')[:8]


	'''
	Checks to see if the hashed nonce matches the expected nonce
	'''
	def is_valid_nonce(self, dest_ip, nonce_value):
		try:
			return self.hash_ip(dest_ip) == nonce_value
		except ValueError:
			ip = self.hex_to_ip(dest_ip)
			return self.hash_ip(ip) == nonce_value


	'''
	This method is responsible for detecting the rate at which traffic flows through the node.
	Each time it a host receives a packet, it creates an entry in a table and keeps track of the amount of traffic that has been sent
	over the last rate_sample_duration seconds. See config file to change the way this function operates. 

	packet - a netfilterqueue packet object that needs to be analyzed
	packet_queue - the queue of packets that need to be checked
	'''
	def check_traffic(self, pkt, packet):
		#We need to get the packet object from netfilterqueue in the form of a scapy packet object
		#I am using dpkt to parse the packet source address here because scapy takes 2.5x longer. 
		packet_len = packet.get_payload_len()
		current_time = time.time()

		if pkt.haslayer(AITF):
			packet_src = pkt[AITF].RR
			#Store the packet length and the time of entry in each mapping
			if packet_src not in route_list:
				print "Added entry for packets from {0}. First packet was {1} bytes in size\n".format(packet_src, packet_len)
				route_list[packet_src] =  ( packet_len, current_time )
			else:
				#If rate_sample_duration seconds have passed, reset the entry
				if current_time - route_list[packet_src][1] >= config_params.rate_sample_duration:
					route_list[packet_src] =  ( packet_len, current_time )
					return
				else:
					#If the source of this packet has sent too much traffic...
					if route_list[packet_src][0] >= config_params.max_bytes:
						#If we don't put this in a thread, the program will hang because 
						#nfqueue will wait for us to accept the packet that send_filter_request sends, and send_filter_request will wait for a response 
						#(which never come because nfqueue hasn't had a chance to accept)
						try:
							send_thread = threading.Thread(target=self.send_filter_request, args=(packet,0) )
							send_thread.start()
							route_list[packet_src] = (0, current_time )
						except:
							pass
					else:
						#Increment the total amount of bytest that this host has sent in recent memory
						route_list[packet_src] = ( route_list[packet_src][0] +  packet_len, route_list[packet_src][1] )


	'''
	Sends a filtering request to the gateway of the victimized host. Described in the paper, the process is:
		1. The victim V sends a filtering request to V gw , specifying an undesired flow F .
		2. The victim?s gateway V gw :
			(a). Installs a temporary filter to block F for T tmp seconds.
			(b). Initiates a 3-way handshake with A gw
			(c). Removes its temporary filter upon completion of the handshake

		3. The attack gateway A gw:
			(1). Responds to the 3-way handshake
			(2). Installs a temporary filter to block F for Ttmp seconds, upon completion of the handshake
			(3). Sends a filtering request to the attack source A, to stop F for Tlong >> Ttmp minutes
	'''

	def send_filter_request(self, packet, escalation_index):	
		#Get the real IP address
		pkt = IP(packet.get_payload())

		#We can't send a filter request without an AITF shim
		if pkt.haslayer(AITF):
			rr_path = pkt[AITF].RR + str(escalation_index)
			print "Sending a filtering request to block traffic from route {0}...\n".format( rr_path )

			#Establish a three way handshake to send a filtering request
			self.three_way_handshake(config_params.local_ip, config_params.gateway_ip, "RRBLOCK:" + rr_path)
		else:
			print "No RR path attached to this packet, can't send filter request out :( "
		return

	'''
	Takes in a packet and adds/updates the packet shim
	'''
	def shim_packet(self, pkt):
		#Hash the destination IP of the packet to generate our nonce
		packet_dest = pkt[IP].dst
		nonce = self.hash_ip(packet_dest)

		#Packet is shimmed already, just update the fields
		if pkt.haslayer(AITF):
			del pkt[AITF].length
			path = pkt[AITF].RR
			path += ( self.ip_to_hex( config_params.local_ip ) + nonce)
			pkt[AITF].RR = path

		#Packet has no shim yet
		else:
			iplayer = pkt[IP]
			payload = pkt.payload
			iplayer.remove_payload()

			aitf = AITF()
			aitf.RR = self.ip_to_hex( pkt.src ) + "ffffffff"
			aitf.RR += ( self.ip_to_hex( config_params.local_ip ) + nonce)
			pkt = iplayer/aitf/payload

		del pkt.chksum
		del pkt.proto
		del pkt.len
		pkt.show2()
		return pkt



	'''
	orig_pkt - a scapy packet that needs an AITF shim
	returns the updated scapy packet, or the same packet if no AITF shim exists
	'''
	def remove_AITF_shim(self, orig_pkt):
		if orig_pkt.haslayer(AITF):
			payload = orig_pkt[AITF].payload
			iplayer = orig_pkt[IP]
			iplayer.remove_payload()

			new_pkt = iplayer/payload
			del new_pkt.chksum
			del new_pkt.proto
			del new_pkt.len
			new_pkt.show2()
			return new_pkt
		return orig_pkt



	'''
	Converts a netfilter packet object to a scapy packet object
	'''
	def nfq_to_scapy(self, nfpacket):
		payload = nfpacket.get_payload()
		return IP(payload)


	'''Issues IP table rules depending on the mode that the program is running in'''
	def setup_commands(self):
		if config_params.mode == "router":
			iptb_forward = "sudo iptables -I FORWARD -d {0} -j NFQUEUE --queue-num 1".format(config_params.local_subnet)
			iptb_input = "sudo iptables -I INPUT -p tcp --dport 80 -d {0} -j NFQUEUE --queue-num 1".format(config_params.local_subnet)
			iptb_probe_input = "sudo iptables -I INPUT -p icmp -d {0} -j NFQUEUE --queue-num 1".format(config_params.local_subnet)
			iptb_probe_output = "sudo iptables -I OUTPUT -p icmp -d {0} -j NFQUEUE --queue-num 1".format(config_params.local_subnet)

			ipv4_forwarding = "sudo sysctl -w net.ipv4.ip_forward=1"
			icmp_send = "echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/send_redirects"
			icmp_accept = "echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/accept_redirects"

			call( iptb_forward.split() )
			call( iptb_input.split() )
			call( iptb_probe_output.split() )
			call( iptb_probe_input.split() )
			call( ipv4_forwarding.split() )
			call( icmp_send.split() )
			call( icmp_accept.split() )

		elif config_params.mode == "host":
			iptb_tcp_input = "sudo iptables -I INPUT -p tcp --dport 80 -d {0} -j NFQUEUE --queue-num 1".format(config_params.local_subnet)
			iptb_input = "sudo iptables -I INPUT ! -p tcp -d {0} -j NFQUEUE --queue-num 1".format(config_params.local_subnet)
			call( iptb_input.split() )
			call( iptb_tcp_input.split() )


	'''
	Flushes iptables rules upon exiting the program
	This function is registered to run at exit
	'''
	def flush_iptables(self):
		flush = "sudo iptables -F"
		delete = "sudo iptables -X"

		call( flush.split() )
		call( delete.split() )


	'''
	Starts netfilterqueue
	'''
	def net_filter(self):
		nfqueue = NetfilterQueue()
		
		try:
			nfqueue.bind(1, self.callback)
			nfqueue.run()
		except KeyboardInterrupt:
			nfqueue.unbind()


def main():
	global config_params
	global route_list
	global shadow_table
	global aitf_routers
	route_list = {} #Stored as a dictionary of xx.xx.xx.xx ip addresses (formed with inet_ntoa) and a tuple of (packet_len , current_time)
	shadow_table = {} #Stored as a dictionary of xx.xx.xx.xx ip addresses (formed with inet ntoa) and a time at which the block will end.
	aitf_routers = {} #Stored as dictionary of IP addresses and a boolean of whether or not the next hop towards this destination is AITF enabled

	config_params = config.Configuration()
	transit = Transit()

	#Set/Flush IP tables
	transit.setup_commands()
	atexit.register(transit.flush_iptables)

	transit.bind_packet_layers()
	transit.net_filter()


	

if __name__ == "__main__":
    main()

