from scapy.all import *
from struct import *
from threading import Thread
from Queue import Queue, Empty
from netfilterqueue import NetfilterQueue
import socket, sys, time
import config

'''This class is used to represent the structure of an AITF shim'''
class AITF(Packet):
	name = "AITF"
	fields_desc = [XBitField("PK",0,48),
	BitField("BytesPerHop",	0,	8),
	BitField("Checksum",	0,	32),
	StrField("RR", None, fmt="H")]



'''The Packet class is responsible for intercepting and sending on modified traffic'''
class Transit():

	'''
		Starts netfilterqueue
	'''
	def net_filter(self):
		nfqueue = NetfilterQueue()
		nfqueue.bind(1, Transit().shim_packet)
		nfqueue.run()


	'''
	Callback function for shimming netfilterqueue packets

	Packet - a binary packet that will be captured, ruthlessly held prisoner by netfilterqueue, 
	and tortured by having and AITF shim shoved under its nails

	'''
	def shim_packet(self, packet):
		#Get the payload of the packet and structure it as a scapy packet object
		payload = packet.get_payload()
		shimmed_packet = IP(payload)

		#Make the AITF shim
		aitf_shim = AITF()
		
		#Move the IP payload onto the AITF shim, 
		#and then glue the AITF shim + new payload back onto the IP layer
		layer = shimmed_packet[IP]
		aitf_shim.add_payload(layer.payload)
		layer.remove_payload()
		layer.add_payload(aitf_shim)
		shimmed_packet.show()

		#Modify the original packet to have the new payload
		packet.set_payload(str(shimmed_packet))
		packet.accept()


	'''
	This method is responsible for detecting the rate at which traffic flows through the node and inserting inserting incoming packets into the queue.
	Each time it recieves traffic from a node, it creates an entry in a table and keeps track of the amount of traffic that has been sent
	over the last rate_sample_duration seconds. See config file to change the way this function operates. 

	packet - a scapy packet object that needs to be analyzed
	packet_queue - the queue of packets that need to be checked
	'''
	def check_traffic(self, packet):
		packet_src = str(packet[IP].src)

		#Store the packet length and the time of entry in each mapping
		if packet_src not in route_list:
			print "Added entry for packets from {0}\n".format(packet_src)
			route_list[packet_src] =  ( len(packet), time.time() )
		else:
			#If rate_sample_duration seconds have passed, reset the entry
			if time.time() - route_list[packet_src][1] >= config_params.rate_sample_duration:
				route_list[packet_src] =  ( len(packet), time.time() )
			else:
				#If the source of this packet has sent too much traffic...
				if route_list[packet_src][0] >= config_params.max_bytes:
					print "Send a filtering request to block traffic from {0}\n".format(packet_src)
				else:
					#Increment the total amount of bytest that this host has sent in recent memory
					route_list[packet_src] = ( route_list[packet_src][0] +  len(packet), route_list[packet_src][1] )


def main():
	global config_params
	global route_list
	route_list = {}
	config_params = config.Configuration()

	Transit().net_filter()
	


if __name__ == "__main__":
    main()

