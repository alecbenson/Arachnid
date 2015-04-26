from subprocess import call
import sys

vm_count = int( input("Enter number of machines on the network: ") )
node_id = int( input("Enter node #: ") )

nodes = range(node_id, vm_count)

for index in nodes:
	call(["sudo", "route", "add", "-host", "10.4.4.{0}".format( str(index + 1) ), "gw", "10.4.4.{0}".format( nodes[1] )] )

nodes = range(1, node_id)
for index in nodes[:node_id-1]:
	call(["sudo", "route", "add", "-host", "10.4.4.{0}".format( str(index) ), "gw", "10.4.4.{0}".format( nodes[-1] )] )
