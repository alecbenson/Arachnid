from scapy.all import *

'''The Packet class is responsible for intercepting and sending on modified traffic'''
class Packet():

	'''
	filter - a string containing filters for deciding what to capture. Example: 'icmp' will only capture icmp packets.
	count - the number of packets to capture. 
	'''
	def capture(self,filter, count):
		return sniff(iface="eth0", filter=filter, count=count)

Packet().capture("icmp",2)
