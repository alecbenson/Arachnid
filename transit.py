from scapy.all import *
from struct import *
from netfilterqueue import NetfilterQueue
from Crypto.Cipher import AES
from subprocess import call
import socket, sys, time, config, random
import binascii, threading, dpkt, atexit

'''Exception for if we get packets that don't have an AITF layer'''
class No_AITF_Shim(Exception):
	pass

'''This class is used to help determine the length of the RR field when decoding packets'''
class XFieldLenField(FieldLenField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))  

'''This class is used to represent the structure of an AITF shim'''
class AITF(Packet):
	name = "AITF"
	fields_desc = [XBitField("PK",0,48),
	BitField("BytesPerHop",	0,	8),
	BitField("PayloadProto", 0, 8),
	BitField("Checksum",	0,	32),
	XFieldLenField("length", 0, length_of="RR", fmt="H"),
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
	def manage_block_request(self, packet, load, escalation_level):
		#1. Set a local filter and once it expires keep an entry in the shadow table
		#An entry is 8 characters long, so we use escalation index as 
		#an index multiplier to find the correct IP address and nonce to block
		escalation_index = 16*escalation_level

		#Agw is the attacker gateway. We can find it in this part of the RR
		agw_IP = self.hex_to_ip( load[ 24 + escalation_index : 32 + escalation_index ] )

		#If we are the attacker's gateway (or the next gateway in the event of escalation)
		if packet.dst == agw_IP:
			nonce = load[32 + escalation_index : 40 + escalation_index]
			if self.is_valid_nonce(agw_IP, nonce):
				#IP address of the attacker. We can find it in this part of the RR
				block_dest = self.hex_to_ip( load[ 8 + escalation_index : 16 + escalation_index ] )
				shadow_table[block_dest] = time.time()
				print "Installed filter: attacker {0} is one hop from me, {1}".format(block_dest,agw_IP)
			else:
				print "Did NOT install filter: attacker has spoofed this path".format(nonce)
		else:
			print "Forwarding the requst to the proper attacker gateway, {0}\n".format( agw_IP )
			self.three_way_handshake( config_params.local_ip, agw_IP, load)


	'''
	Initiates a three way handshake between source IP and destination IP with payload 'payload'
	'''
	def three_way_handshake(self, src, dst, payload):
				#Form the requst packet and shove the RR path in the payload
		sport = random.randint(1024,65535)
		seq= random.randint(1,100000)

		#three way hannnndshakkeeeee!! (whaaat)
		ip = IP(src=src, dst=dst )
		tcp_syn = TCP(sport=sport, dport=80, flags='S', seq=seq)
		tcp_synack = sr1(ip/tcp_syn)

		#Respond with final ack!
		#Note that there is a slight complication here. 
		#Because of the way scapy works, the host is actually totally unaware that we are trying to open up a TCP connection.
		#When it gets the synack back, our own host freaks out and tries to reset the connection.
		#We can solve this by blocking outbound reset packets with an Ip table rule, but for now we'll just blissfully pretend that everything is okay. 
		tcp_ack = TCP(sport=sport, dport=80, flags='A', seq=tcp_synack.ack, ack=tcp_synack.seq + 1)
		send(ip/tcp_ack)

		#Send the payload over
		tcp_send = TCP(sport=sport, dport=80, flags="PA", seq=tcp_synack.ack, ack=tcp_synack.seq + 1)
		send(ip/tcp_send/payload)

	
	'''
	Probes the next hope for AITF support by sending a packet with TTL 1 and looking for code 2 in the response.
	We use code 2 because it is never used for Time Exceeded ICMP responses and we can use it to identify AITF enabled routers
	'''
	def probe_AITF(self, packet):
		if packet.dst in aitf_routers:
			return aitf_routers[packet.dst]

		probe = IP(src=config_params.local_ip, dst=packet.dst, ttl=1)/ICMP(code=4)
		response = sr1(probe,timeout=1)
		response.show()

		#We got a response from the next hop and it is not the host
		if response.type == 11:
			if response[ICMPerror].code == 2:
				aitf_routers[packet.dst]=True
				return True
			else:
				aitf_routers[packet.dst]=False
				return False
		#We have reached the end host
		elif packet.dst == response.src:
			aitf_routers[packet.dst]=True
			return True
		return False
		

	'''
	Callback function for NfQueue. 
	If the machine is in "host" mode, then it will check to see if it is receiving too much traffic.
	If the machine is in "router" mode, then it will shim packets
	'''
	def callback(self, packet):
		pkt = IP(packet.get_payload())

		#Intercept ICMP Time Exceeded Packets and indicate that we are AITF enabled
		if pkt.haslayer(ICMP):
			#We got probed by another router, set AITF code 2 in response
			if pkt[ICMP].code == 4:
				pkt[ICMP].code = 2
				packet.set_payload( str(pkt) )
				packet.accept()
				return

		if config_params.mode == "router":
			#Check to make sure the source isn't blocked
			if pkt.src in shadow_table:
				time_left = (shadow_table[pkt.src] + config_params.filter_duration) - time.time()
				if time_left > 0:
					print "Dropping packet from {0}. Still {1} seconds left in filter".format(pkt.src, time_left)
					packet.drop()
					return

			#We check if the next hop is AITF enabled and shim packets if it is. Otherwise, continue to send legacy packets
			if not self.probe_AITF(pkt):
				packet.accept()
				print "Next hop not enabled: not shimming\n"
				return


			#If the packet is destined to the router, we are likely receiving a block reqeuest
			if pkt.dst == config_params.local_ip:
				if pkt.haslayer(TCP) & pkt.haslayer(Raw):
					pkt.show()
					load = str(pkt[Raw].load)
					if "RRBLOCK:" in load:
						self.manage_block_request(pkt, load, 0)
			else:
				#Packet is already shimmed
				if pkt.haslayer(AITF):
					pkt = self.update_AITF_shim(pkt)
				#Packet has not been shimmed yet
				else:
					pkt = self.add_AITF_shim(pkt)
					
				#Show2 will conveniently recalculate the IP checksum for us
				del pkt.chksum
				pkt.show2()
				#Pack the packet with the new data
				packet.set_payload( str(pkt) )

		elif config_params.mode == "host":
			self.check_traffic(packet)
			
			#Chop the AITF shim off so the OS can interpret it
			pkt = self.remove_AITF_shim(pkt)
			packet.set_payload( str(pkt) )
			
		else:
			print "Unrecognized mode set in the config: {0}\n".format(config_params.mode)
			sys.exit()
		packet.accept()


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
	def check_traffic(self, packet):
		#We need to get the packet object from netfilterqueue in the form of a scapy packet object
		#I am using dpkt to parse the packet source address here because scapy takes 2.5x longer. 
		packet_src = socket.inet_ntoa( dpkt.ip.IP(packet.get_payload()).src )
		packet_len = packet.get_payload_len()
		current_time = time.time()

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
						send_thread = threading.Thread(target=self.send_filter_request, args=(packet,) )
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

	def send_filter_request(self, packet):
		#Get the real IP address
		pkt = IP(packet.get_payload())

		#We can't send a filter request without an AITF shim
		if pkt.haslayer(AITF):
			rr_path = pkt[AITF].RR
			print "Sending a filtering request to block traffic from route {0}...\n".format( rr_path )

			#Establish a three way handshake to send a filtering request
			self.three_way_handshake(config_params.local_ip, config_params.gateway_ip, "RRBLOCK:" + rr_path)
		else:
			print "No RR path attached to this packet, can't send filter request out :( "
		return


	'''
	Takes in a shimmed scapy packet object and updates the AITF fields accordingly
	'''
	def update_AITF_shim(self, packet):
		#Hash the destination IP of the packet to generate our nonce
		packet_dest = packet[IP].dst
		nonce = self.hash_ip(packet_dest)

		#Get eth0's ip address to store in the RR
		path = packet[AITF].RR

		#Path is empty
		if not path:
			path += self.ip_to_hex( packet.src ) + "ffffffff"
			packet[AITF].length += 16

		path += ( self.ip_to_hex( config_params.local_ip ) + nonce)
		packet[AITF].RR = path
		packet[AITF].length += 16

		return packet


	'''
	orig_pkt - a scapy packet that needs an AITF shim
	returns the updated scapy packet
	'''
	def add_AITF_shim(self, orig_pkt):
		#Get the packet and structure it as a scapy packet object

		iplayer = orig_pkt[IP]
		iplayer.proto = 145
		payload = orig_pkt.payload
		iplayer.remove_payload()

		aitf = AITF()
		new_pkt = iplayer/aitf/payload
		new_pkt = self.update_AITF_shim(new_pkt)

		return new_pkt



	'''
	orig_pkt - a scapy packet that needs an AITF shim
	returns the updated scapy packet
	'''
	def remove_AITF_shim(self, orig_pkt):
		if orig_pkt.haslayer(AITF):
			iplayer = orig_pkt[IP]
			payload = orig_pkt[AITF].payload
			iplayer.remove_payload()

			new_pkt = iplayer/payload
			return new_pkt
		else:
			raise No_AITF_Shim("Tried to remove non-existent AITF layer")
			return



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
			iptb_tcp_input = "sudo iptables -I INPUT -p tcp --dport 80 -d {0} -j NFQUEUE --queue-num 1".format(config_params.local_subnet)		
			iptb_probe_input = "sudo iptables -I INPUT -p icmp -d {0} -j NFQUEUE --queue-num 1".format(config_params.local_subnet)
			ipv4_forwarding = "sudo sysctl -w net.ipv4.ip_forward=1"
			icmp_send = "echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/send_redirects"
			icmp_accept = "echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/send_redirects"

			call( iptb_forward.split() )
			call( iptb_tcp_input.split() )
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
	route_list = {}
	shadow_table = {}
	aitf_routers = {}

	config_params = config.Configuration()
	transit = Transit()

	#Set/Flush IP tables
	transit.setup_commands()
	atexit.register(transit.flush_iptables)

	transit.bind_packet_layers()
	transit.net_filter()
	

if __name__ == "__main__":
    main()

