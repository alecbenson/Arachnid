import ConfigParser, sys

class Configuration():
	def __init__(self):
		try:
			section_name = "AITF"
			config = ConfigParser.RawConfigParser()
			config.read("config.cfg")

			#Is AITF enabled on this node?
			self.enabled = config.getboolean( section_name, "enabled")

			#How long should a block last?
			self.filter_duration = config.getint( section_name, "filter_duration")

			#How long should a temporary filter last?
			self.temp_filter_duration = config.getint( section_name, "temp_filter_duration" )

			#What is the max amount of traffic we can allow in 10s?
			self.max_bytes_10s = config.getint( section_name, "max_bytes_10s")

			#What is the ID of this node in the network?
			self.node_id = config.getint( section_name, "node_id")

			#How many nodes are on the network?
			self.node_count = config.getint( section_name, "node_count")

			#What is the public key associated with this node?
			self.node_public_key = config.get( section_name, "node_public_key")

			#Iterate through private keys and store them in node_keys
			self.node_keys = []
			for index in range(self.node_count):
				node_key = config.get( section_name, "node{0}_key".format(index) )
				self.node_keys.insert(index, node_key)

		except ConfigParser.NoOptionError:
			print "Error parsing configuration. Invalid option provided"
			sys.exit()


