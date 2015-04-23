from scapy.all import *
from struct import *
import socket, sys
import aitf.py

'''The Packet class is responsible for intercepting and sending on modified traffic'''
class Packet():

	'''
	filter - a string containing filters for deciding what to capture. Example: 'icmp' will only capture icmp packets.
	count - the number of packets to capture. 
	returns a list of captured packets
	'''
	def capture(self,filter, count):
		return sniff(iface="eth0", filter=filter, count=count)


	'''
	Generates an AITF shim header
	'''
	def generate_AITF_header(self, source_ip, dest_ip):
		#TODO - put the logic for making an AITF shim in here
		return 0


	'''
	Generates an IP header for use in constructing packets
	'''
	def generate_IP_header(self, source_ip, dest_ip):
		# ip header fields
		ip_ihl = 5 #Internet header length
		ip_ver = 4 #IP Version (always 4 in our case)
		ip_tos = 0 #Type of service
		ip_tot_len = 0  #kernel will fill the correct total length
		ip_id = 54321   #Id of this packet
		ip_frag_off = 0 #Fragmentation offset
		ip_ttl = 255 #Time to live
		ip_proto = socket.IPPROTO_TCP #Communication protocol
		ip_check = 0    #kernel will fill the correct checksum
		ip_saddr = socket.inet_aton ( source_ip )
		ip_daddr = socket.inet_aton ( dest_ip )
		ip_ihl_ver = (ip_ver << 4) + ip_ihl

		#Construct the IP Header
		return pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)	


	'''
	Generates a TCP header for use in constructing packets
	'''
	def generate_TCP_header(self, source_ip, dest_ip, user_data):
		#TCP header fields
		tcp_source_port = 1234   # source port
		tcp_dest_port = 80   # destination port
		tcp_seq = 454
		tcp_ack_seq = 0
		tcp_doff = 5    #4 bit field, size of TCP header, 5 * 4 = 20 bytes

		#TCP flags
		tcp_fin = 0
		tcp_syn = 1
		tcp_rst = 0
		tcp_psh = 0
		tcp_ack = 0
		tcp_urg = 0
		tcp_window = socket.htons (5840)    #maximum allowed window size
		tcp_check = 0
		tcp_urg_ptr = 0

		tcp_offset_res = (tcp_doff << 4) + 0
		tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

		# the ! in the pack format string means network order
		tcp_header = pack('!HHLLBBHHH' , tcp_source_port, tcp_dest_port, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

		# pseudo header fields
		source_address = socket.inet_aton( source_ip )
		dest_address = socket.inet_aton(dest_ip)
		placeholder = 0
		protocol = socket.IPPROTO_TCP
		tcp_length = len(tcp_header) + len(user_data)

		psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
		psh = psh + tcp_header + user_data;

		tcp_check = checksum(psh)

		# make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
		return pack('!HHLLBBH' , tcp_source_port, tcp_dest_port, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)


	'''
	Composes a complete packet
	'''
	def generate_packet(self, source_ip, dest_ip, user_data):
		packet = ''
		ip_header = self.generate_IP_header(source_ip, dest_ip)
		tcp_header = self.generate_TCP_header(source_ip, dest_ip, user_data)
		return ip_header + tcp_header + user_data


	'''
	Sends a packet across the network
	'''
	def send_packet(self, source_ip, dest_ip, user_data):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		except socket.error, msg:
			print('Socket could not be created. Error code: ' + str(msg[0]) + ' Message: ' + str(msg[1]))
			sys.exit()

		packet = self.generate_packet(source_ip, dest_ip, user_data)
		s.sendto(packet, (dest_ip , 0 ))



Packet().send_packet("192.168.1.116", "192.168.1.104", "This is a test")