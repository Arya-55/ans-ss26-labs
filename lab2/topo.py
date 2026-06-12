"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

from typing import Literal

# Class for a node in the graph
class Node:

	def __init__(self, *, name,  pod, switch, id, type: Literal["core", "aggr", "edge", "serv"]):
		self.neighbors: list[Node] = []
		self.name = name
		self.type = type						# core | aggregation | edge | server
		self.net = 10
		self.pod = pod							# k if core switch, pod_identifier for everything else
		self.switch = switch					# [1, k/2] for core switches, [1, k] for pod switches
		self.id = id							# 1 for all switches in one pod, [2, k/2+1] for servers, [1, k/2] for core switches
		self.ip_address = f"{self.net}.{self.pod}.{self.switch}.{self.id}"
		self.mac = None
		self.dpid = int(name[1:])
		self.ports: dict[int, int] = {}  		# dpid: to port_no
		self.unexplored_ports = set()
		self.next_hop: dict[str, Node] = {}  	# dpid: Node


	# Add an edge connected to another node
	def add_edge(self, node):
		self.neighbors.append(node)
		node.neighbors.append(self)
		return Edge(self, node)
	

	# Remove an edge to a neighbor
	def remove_edge(self, node):
		if self.is_neighbor(node):
			self.neighbors.remove(node)
			node.neighbors.remove(self)
		else:
			print(f"Couldn't remove edge, node is no neighbor.")


	# Decide if another node is a neighbor
	def is_neighbor(self, node):
		return node in self.neighbors


# Class for an edge in the graph
class Edge:
	def __init__(self, lnode: Node, rnode: Node):
		self.lnode = lnode
		self.rnode = rnode

class Fattree:

	def __init__(self, num_ports, do_sanity_check=True):
		self._next_dpid = 1
		self._next_host_dpid = 21
		self.k = num_ports
		self.switches = []			# core, aggregation and edge switches
		self.servers = []			# servers, aka leaf nodes
		self.edges = []				# save edges here instead of in the nodes
		self.generate(num_ports)
		if do_sanity_check: self.sanity_check()


	def next_dpid(self):
		current_dpid = self._next_dpid
		self._next_dpid += 1
		return current_dpid


	def next_host_dpid(self):
		current_host_dpid = self._next_host_dpid
		self._next_host_dpid += 1
		return current_host_dpid
	

	def generate(self, num_ports: int):
		# "There are k[=num_ports] pods, each containing two layers of k/2 switches. 
		# Each k-port switch in the lower layer is directly connected to k/2 hosts 
		# Each of the remaining k/2 ports is connected to k/2 of the k ports in the aggregation layer of the hierarchy.
		# There are (k/2)^2 k-port core switches. Each core switch has one port connected to each of k pods. 
		# The i-th port of any core switch is connected to pod i such that consecutive ports in the aggregation layer 
		# of each pod switch are connected to core switches on (k/2) strides. 
		# In general, a fat-tree built with k-port switches supports k^3/4 hosts. 
		# In this paper, we focus on designs up to k = 48. 
		# Our approach generalizes to arbitrary values for k." (Should be even tho lol)
		# -> Fat-Tree paper page 66

		# Ensure that we can built the topology
		assert num_ports % 2 == 0, f"The parameter num_ports has to be an even number (is {num_ports}) for the topology to work."

		k = num_ports
		k_half = int(k/2)
		print(f"Building a Fat-Tree with {k} ports ({int(k ** 3 / 4)} Servers, {k_half} Edge/Aggr Switches per Pod, {(k_half) ** 2} Core Switches)")

		# create Core Switches
		core_counter = 0
		core_switches = []
		for j in range(1, k_half + 1):
			for i in range(1, k_half + 1):
				core_counter += 1
				core_switches.append(Node(name=f"s{core_counter}", pod=k, switch=j, id=i, type="core"))
		self.switches += core_switches

		# Iterate over pods to generate and connect the switches and servers in them
		edge_counter = core_counter + int(k * k / 2)
		aggr_counter = core_counter
		serv_counter = core_counter + 2 * int(k * k / 2)
		for pod_id in range(k):
			edge_switches = []
			aggr_switches = []

			# add pod switches, all have the id=1 in the last position
			for switch_id in range(k):
				if switch_id < (k_half):
					# add edge switch
					edge_counter += 1
					edge_switch = Node(name=f"s{edge_counter}", pod=pod_id, switch=switch_id, id=1, type="edge")

					# add servers and connect them to edge switch
					servers = []
					for host_id in range(2, k_half + 2):
						serv_counter += 1
						server = Node(name=f"h{serv_counter}", pod=pod_id, switch=switch_id, id=host_id, type="serv")
						servers.append(server)
						edge = edge_switch.add_edge(server)
						self.edges.append(edge)

					edge_switches.append(edge_switch)
					self.servers += servers
				else:
					# add aggr switch
					aggr_counter += 1
					aggr_switch = Node(name=f"s{aggr_counter}", pod=pod_id, switch=switch_id, id=1, type="aggr")

					# connect to edge switches
					for edge_switch in edge_switches:
						edge = aggr_switch.add_edge(edge_switch)
						self.edges.append(edge)

					# connect to core switches
					for offset in range(k_half):
						# modulo finds the leftmost group of core switches based on the aggr_switch, 
						# multiplication gives the starting index of that group in the list
						# offset moves index to the actual index 
						core_switch = core_switches[(switch_id % k_half) * k_half + offset]
						
						# sanity checks to make sure we are connecting to the correct core switch 
						assert core_switch.switch == (switch_id % k_half) + 1
						assert core_switch.id == offset + 1

						# connecting
						edge = core_switch.add_edge(aggr_switch)
						self.edges.append(edge)

					aggr_switches.append(aggr_switch)
			self.switches += edge_switches + aggr_switches


	def sanity_check(self):
		print("Sanity Check for generated topology:")

		num_servers = int(self.k ** 3 / 4)
		num_core_switches = int(self.k / 2) ** 2						# formula from paper
		num_pod_layer_switches = int(self.k ** 2 / 2) 					# k/2 per pod for k pods
		num_switches = num_core_switches + 2 * num_pod_layer_switches 
		num_edges = num_pod_layer_switches * self.k + num_servers		
		# edges between switches are one for each port on the aggr switches, overall edges also include those to servers

		print(f" - Number of Servers:      \tshould be {num_servers},\t is {len(self.servers)}")
		print(f" - Number of Switches:     \tshould be {num_switches},\t is {len(self.switches)}")
		print(f" - Number of Edge Switches:\tshould be {num_pod_layer_switches},\t is {len([x for x in self.switches if x.type == 'edge'])}")
		print(f" - Number of Aggr Switches:\tshould be {num_pod_layer_switches},\t is {len([x for x in self.switches if x.type == 'aggr'])}")
		print(f" - Number of Core Switches:\tshould be {num_core_switches},\t is {len([x for x in self.switches if x.type == 'core'])}")
		print(f" - Number of Pods:         \tshould be {self.k},\t is {len(set([x.pod for x in self.switches if x.type == 'aggr']))}")
		print(f" - Number of Edges:        \tshould be {num_edges},\t is {len(self.edges)}")
		print(f"All Servers need to have just one neighbor: {all([len(x.neighbors) == 1 for x in self.servers])}")
		print(f"The neighbors of all Servers must be edge switches: {all([n.type == 'edge' for x in self.servers for n in x.neighbors])}")
		print(f"All Switches need to have {self.k} neighbors: {all([len(x.neighbors) == self.k for x in self.switches])}")

		core_check = True
		pod_check = True
		for switch in self.switches:
			# If something is wrong, set value to False

			match switch.type:
				case "core":
					# each core switch is connected to exactly one aggr switch in one pod
					if any([n.pod == self.k for n in switch.neighbors]):
						print(f"ERROR: Core switch with IP {switch.ip_address} is connected to another Core Switch")
						core_check = False
					if not all(n.type == "aggr" for n in switch.neighbors):
						print(f"ERROR: Core switch with IP {switch.ip_address} has non-aggr switches as neighbors")
						core_check = False 
					if not sorted([n.pod for n in switch.neighbors]) == list(range(self.k)):
						print(f"ERROR: Core switch with IP {switch.ip_address} has not one connection to each pod")
						core_check = False 
				case "edge":
					# all connections that are not to servers are to aggr switches in the same pod
					aggr_neighbors = [n for n in switch.neighbors if n.type == "aggr"]
					if len(aggr_neighbors) != int(self.k / 2):
						print(f"ERROR: Edge switch with IP {switch.ip_address} has the wrong number of aggr neighbors")
						pod_check = False
					if not all([an.pod == switch.pod for an in aggr_neighbors]):
						print(f"ERROR: Edge switch with IP {switch.ip_address} is connected to aggr switch from different pod")
						pod_check = False
				case "aggr":
					# all connections that are not to core switches are to edge switches in the same pod
					edge_neighbors = [n for n in switch.neighbors if n.type == "edge"]
					if len(edge_neighbors) != int(self.k / 2):
						print(f"ERROR: Aggr switch with IP {switch.ip_address} has the wrong number of edge neighbors")
						pod_check = False
					if not all([en.pod == switch.pod for en in edge_neighbors]):
						print(f"ERROR: Aggr switch with IP {switch.ip_address} is connected to edge switch from different pod")
						pod_check = False
				case _:
					raise AssertionError(f"Unexpected switch.type: {switch.type}")
				
		if core_check:
			print(f"Each core switch needs to be connected to exactly one aggr switch of each pod: {core_check}")
		if pod_check:
			print(f"Edge and aggr switches may only be interconnected within one pod: {pod_check}")
		print()

