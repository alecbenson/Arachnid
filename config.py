import ConfigParser, sys

class Configuration():
	def __init__(self):
		try:
			aitf_section = "AITF"
			router_section = "Router Config"
			host_section = "Host Policy Module"
			network_section = "Network Config"

			config = ConfigParser.RawConfigParser()
			config.read("config.cfg")

			'''################## AITF SECTION ##################'''
			#Is this machine a host or a router?
			self.mode = config.get( aitf_section, "mode")


			'''################## ROUTER SECTION #################'''
			#How long should a block last?
			self.filter_duration = config.getint( router_section, "filter_duration")

			#How long should a temporary filter last?
			self.temp_filter_duration = config.getint( router_section, "temp_filter_duration" )

			#The secret key used to generate nonces
			self.node_secret_key = config.get( router_section, "node_secret_key")


			'''################## HOST SECTION ###################'''
			#What is the max amount of traffic we can allow in rate_sample_duration seconds?
			self.max_bytes = config.getint( host_section, "max_bytes")

			#We check for 'max_bytes' bytes of traffic per 'rate_sample_duration' seconds to decide if we should issue a filtering request
			self.rate_sample_duration = config.getint( host_section, "rate_sample_duration")

			self.gateway_ip = config.get( host_section, "gateway_ip")


			'''################# NETWORK SECTION#################'''
			self.local_subnet = config.get( network_section, "local_subnet" )

		except ConfigParser.NoOptionError:
			print "Error parsing configuration. Invalid option provided"
			sys.exit()


