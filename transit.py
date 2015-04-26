from scapy.all import *
from struct import *
from netfilterqueue import NetfilterQueue
from Crypto.Cipher import AES
import socket, sys, time, config, random, binascii, netifaces as ni, threading, dpkt

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
	XFieldLenField("length", None, length_of="RR", fmt="H"),
	StrLenField("RR", "", length_from=lambda x:x.length)]



'''The Packet class is responsible for intercepting and sending on modified traffic'''
class Transit():

	'''
	Callback function for NfQueue. 
	If the machine is in "host" mode, then it will check to see if it is receiving too much traffic.
	If the machine is in "router" mode, then it will shim packets
	'''
	def callback(self, packet):
		if config_params.mode == "router":
			packet.set_payload( self.shim_packet(packet) )
		elif config_params.mode == "host":
			self.check_traffic(packet)
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
		return self.hash_ip(dest_ip) == nonce_value


	'''Sends a filtering request to a node'''
	def send_filter_request(self, RR_path):
		#Get the real IP address
		dst_ip = str( self.hex_to_ip(RR_path[:8]) )
		print "Sending a filtering request to block traffic from {0}...\n".format(dst_ip)

		#Form the requst packet and shove the RR path in the payload
		packet = IP(dst=dst_ip)/TCP(dport=80, flags="S")/str(RR_path)
		response = sr1(packet)
		return


	'''
	Takes in a shimmed scapy packet object and updates the AITF fields accordingly
	'''
	def update_AITF_shim(self, packet):
		try:
			#Hash the destination IP of the packet to generate our nonce
			packet_dest = packet[IP].dst
			nonce = self.hash_ip(packet_dest)

			#Get eth0's ip address to store in the RR
			local_ip = ni.ifaddresses('eth0')[2][0]['addr']
			packet[AITF].RR += ( self.ip_to_hex(local_ip) + nonce)
		except:
			print "Error updating packet shim!\n"

		return packet


	'''
	Converts a netfilter packet object to a scapy packet object
	'''
	def nfq_to_scapy(self, nfpacket):
		payload = nfpacket.get_payload()
		return IP(payload)


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


	'''
	Packet - a binary packet that will be captured, ruthlessly held prisoner by netfilterqueue, 
	and tortured by having and AITF shim sho
	ved under its nails
	'''
	def shim_packet(self, packet):
		#Get the packet and structure it as a scapy packet object
		orig_pkt = IP(packet.get_payload())

		iplayer = orig_pkt[IP]
		iplayer.proto = 145
		payload = orig_pkt.payload
		iplayer.remove_payload()


		aitf = AITF()
		new_pkt = iplayer/aitf/payload
		new_pkt = self.update_AITF_shim(new_pkt)

		#We need to recalculate the IP checksum or else the shimmed packet will get dropped at the next hop
		del new_pkt.chksum
		#Show2 will rebuild the checksum
		new_pkt.show2()


		return str(new_pkt)



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
						send_thread = threading.Thread(target=self.send_filter_request, args=["c0a80174609e044f"] )
						send_thread.start()
						route_list[packet_src] = (0, current_time )
					except:
						pass
				else:
					#Increment the total amount of bytest that this host has sent in recent memory
					route_list[packet_src] = ( route_list[packet_src][0] +  packet_len, route_list[packet_src][1] )


def main():
	global config_params
	global route_list
	route_list = {}
	#AITF packets use IP proto #145 and can be identified this way
	#These bindings help us decide how to interpret the payload of the packet
	bind_layers(IP, AITF, proto=145)
	bind_layers(AITF, TCP, PayloadProto=6)
	bind_layers(AITF, ICMP, PayloadProto=1)
	bind_layers(AITF, UDP, PayloadProto=17)

	config_params = config.Configuration()
	Transit().net_filter()
	

if __name__ == "__main__":
    main()

