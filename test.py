from scapy.all import *
from struct import *
from threading import Thread
from Queue import Queue, Empty
import socket, sys


'''The Packet class is responsible for intercepting and sending on modified traffic'''
class Packet():
	'''
	Worker function to sniff packets
	packet_queue - the queue to put sniffed packets into
	filter - the string to filter sniffed packets with
	'''
	def capture(self, packet_queue, filter):
		#Note: prn is a callback parameter and is used to store the sniffed packet into the queue
		sniff(iface="eth0", filter=filter, prn = lambda x : packet_queue.put(x) )


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
				packet.show()
				#sendp(packet)
			except Empty:
				print "Packet queue has been empty for {0} second(s)".format(queue_timeout)
				pass

	'''
	TODO: Generates an AITF shim header
	'''
	def generate_AITF_header(self, source_ip, dest_ip):
		#TODO - put the logic for making an AITF shim in here
		return 0

Packet().capture_thread("icmp and host 192.168.1.104",1)

