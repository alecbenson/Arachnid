from scapy.all import *
from struct import *
from threading import Thread
from Queue import Queue, Empty
import socket, sys
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
	Worker function to sniff packets
	packet_queue - the queue to put sniffed packets into
	filter - the string to filter sniffed packets with
	'''
	def capture(self, packet_queue, filter):
		#Note: prn is a callback parameter and is used to store the sniffed packet into the queue
		sniff(iface="eth0", filter=filter, prn = lambda pkt : packet_queue.put(pkt) )

	'''
	Shims the packet with an AITF header
	'''
	def shim_packet(self, packet):
		aitf_shim = AITF()
		layer = packet[IP]
		aitf_shim.add_payload(layer.payload)
		layer.remove_payload()

		#This will shove our AITF shim between layers 3 and 4
		layer.add_payload(aitf_shim)
		return packet


	'''
	This class is where all the magic happens
	filter - a string containing filters for deciding what to capture. Example: 'icmp' will only capture icmp packets.
	queue_timeout - how long to wait for a packet to enter the queue before complaining
	'''
	def capture_thread(self,filter, queue_timeout):
		print "Packet capture thread started"

		#Creates a queue for all captured packets
		packet_queue = Queue()

		sniffer = Thread( target=self.capture, args=(packet_queue, filter) )
		sniffer.daemon = True
		sniffer.start()

		#Take a packet from the queue, print the summary of the packet, wait up to 1 second for a packet to arrive
		while True:
			try:
				packet = packet_queue.get(timeout = queue_timeout)
				packet = self.shim_packet(packet)

				#This is just test code in place now for fucking around with echo replies
				if(packet[IP].src == "192.168.1.104"):
					temp = packet[Ether].src
					packet[Ether].src = packet[Ether].dst
					packet[Ether].dst = temp
					packet[IP].src = "192.168.1.11"
					packet[IP].dst = "192.168.1.104"
					packet[AITF].RR = "FUCK YEAH"
					packet.show()

					sendp(packet)
			except Empty:
				print "Packet queue has been empty for {0} second(s)".format(queue_timeout)
				pass

def main():
	global config_params
	#Transit().capture_thread("icmp and host 192.168.1.104",1)
	
	#Parse config file
	config_params = config.Configuration()


if __name__ == "__main__":
    main()

