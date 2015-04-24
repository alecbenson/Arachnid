from scapy.all import *
from struct import *
from netfilterqueue import NetfilterQueue
from Crypto.Cipher import AES
import socket, sys, time, config, random, binascii, netifaces as ni

'''This class is used to represent the structure of an AITF shim'''
class AITF(Packet):
	name = "AITF"
	fields_desc = [XBitField("PK",0,48),
	BitField("BytesPerHop",	0,	8),
	BitField("Checksum",	0,	32),
	StrField("RR", "", fmt="H")]



'''The Packet class is responsible for intercepting and sending on modified traffic'''
class Transit():

	'''
	Callback function for NfQueue. 
	If the machine is in "host" mode, then it will check to see if it is receiving too much traffic.
	If the machine is in "router" mode, then it will shim packets
	'''
	def callback(self, packet):
		if config_params.mode == "router":
			self.shim_packet(packet)
		elif config_params.mode == "host":
			self.check_traffic(packet)
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
		nfqueue.bind(1, self.callback)
		nfqueue.run()


	'''
	Packet - a binary packet that will be captured, ruthlessly held prisoner by netfilterqueue, 
	and tortured by having and AITF shim shoved under its nails
	'''
	def shim_packet(self, packet):
		#Get the packet and structure it as a scapy packet object
		shimmed_packet = self.nfq_to_scapy(packet)

		#Make the AITF shim
		aitf_shim = AITF()
		
		#Move the IP payload onto the AITF shim, 
		#and then glue the AITF shim + new payload back onto the IP layer
		layer = shimmed_packet[IP]
		aitf_shim.add_payload(layer.payload)
		layer.remove_payload()
		layer.add_payload(aitf_shim)

		#Test to update shim fields
		shimmed_packet = self.update_AITF_shim(shimmed_packet)
		shimmed_packet.show()

		#Modify the original packet to have the new payload
		packet.set_payload(str(shimmed_packet))
		#print str(shimmed_packet)

		packet.accept()


	'''
	This method is responsible for detecting the rate at which traffic flows through the node and inserting inserting incoming packets into the queue.
	Each time it recieves traffic from a node, it creates an entry in a table and keeps track of the amount of traffic that has been sent
	over the last rate_sample_duration seconds. See config file to change the way this function operates. 

	packet - a netfilterqueue packet object that needs to be analyzed
	packet_queue - the queue of packets that need to be checked
	'''
	def check_traffic(self, packet):
		#We need to get the packet object from netfilterqueue in the form of a scapy packet object
		pkt = self.nfq_to_scapy(packet)

		packet_src = str(pkt[IP].src)

		#Store the packet length and the time of entry in each mapping
		if packet_src not in route_list:
			print "Added entry for packets from {0}\n".format(packet_src)
			route_list[packet_src] =  ( len(pkt), time.time() )
		else:
			#If rate_sample_duration seconds have passed, reset the entry
			if time.time() - route_list[packet_src][1] >= config_params.rate_sample_duration:
				route_list[packet_src] =  ( len(pkt), time.time() )
			else:
				#If the source of this packet has sent too much traffic...
				if route_list[packet_src][0] >= config_params.max_bytes:
					print "Send a filtering request to block traffic from {0}\n".format(packet_src)
				else:
					#Increment the total amount of bytest that this host has sent in recent memory
					route_list[packet_src] = ( route_list[packet_src][0] +  len(pkt), route_list[packet_src][1] )


def main():
	global config_params
	global route_list
	route_list = {}
	config_params = config.Configuration()

	Transit().net_filter()
	


if __name__ == "__main__":
    main()

