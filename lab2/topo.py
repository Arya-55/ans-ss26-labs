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


# Class for an edge in the graph
class Edge:
	def __init__(self, lnode: Node, rnode: Node):
		self.lnode = lnode
		self.rnode = rnode


# Class for a node in the graph
class Node:
	def __init__(self, *, pod, switch, id, type: Literal["core", "aggr", "edge", "serv"]):
		self.neighbors = []
		self.type = type				# core | aggregation | edge | server
		self.net = 10
		self.pod = pod					# k if core switch, pod_identifier for everything else
		self.switch = switch			# [1, k/2] for core switches, [1, k] for pod switches
		self.id = id					# 1 for all switches in one pod, [2, k/2+1] for servers, [1, k/2] for core switches
		self.ip_address = f"{self.net}.{self.pod}.{self.switch}.{self.id}"

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


class Fattree:

	def __init__(self, num_ports):
		self.k = num_ports
		self.switches = []			# core, aggregation and edge switches
		self.servers = []			# servers, aka leaf nodes
		self.edges = []				# save edges here instead of in the nodes
		self.generate(num_ports)


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
		print(f"Building a Fat-Tree with {k} ports\n\t=> {k ** 3 / 4} Servers\n\t=>{k_half} Edge/Aggr Switches per Pod\n\t=>{(k_half) ** 2} Core Switches")

		# create Core Switches
		core_switches = []
		for j in range(1, k_half):
			for i in range(1, k_half):
				core_switches.append(Node(pod=k, switch=j, id=i, type="core"))
		self.switches = core_switches

		# Iterate over pods to generate and connect the switches and servers in them
		for pod_id in range(k):
			edge_switches = []
			aggr_switches = []

			# add pod switches, all have the id=1 in the last position
			for switch_id in range(k):
				if switch_id < (k/2):
					# add edge switch
					edge_switch = Node(pod=pod_id, switch=switch_id, id=1, type="edge")
					
					# add servers and connect them to edge switch
					servers = []
					for host_id in range(1, k_half):
						server = Node(pod=pod_id, switch=switch_id, id=host_id, type="serv")
						edge = edge_switch.add_edge(server)
						self.edges.append(edge)

					edge_switches.append(edge_switch)
					self.servers += servers
				else:
					# add aggr switch
					aggr_switch = Node(pod=pod_id, switch=switch_id, id=1, type="aggr")

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
			self.switches += aggr_switches + edge_switches  


	def sanity_check(self):
		print("Sanity Check for generated topology:")

		num_core_switches = int(self.k / 2) ** 2						# formula from paper
		num_pod_layer_switches = int(self.k ** 2 / 2) 					# k/2 per pod for k pods
		num_switches = num_core_switches + num_pod_layer_switches 
		num_edges = num_switches * self.k								# each switch needs to have all ports connected

		print(f" - Number of Servers:      \tshould be {int(self.k ** 3 / 4)},\t is {len(self.servers)}")
		print(f" - Number if Switches:     \tshould be {num_switches},\t is {len(self.switches)}")
		print(f" - Number of Edge Switches:\tshould be {num_pod_layer_switches},\t is {len([x for x in self.switches if x.type == "edge"])}")
		print(f" - Number of Aggr Switches:\tshould be {num_pod_layer_switches},\t is {len([x for x in self.switches if x.type == "aggr"])}")
		print(f" - Number of Core Switches:\tshould be {num_core_switches},\t is {len([x for x in self.switches if x.type == "core"])}")
		print(f" - Number of Pods:		   \tshould be {self.k},\t is {len(set([x.pod for x in self.switches if x.type == "aggr"]))}")
		print(f" - Number of Edges:        \tshould be {num_edges},\t is {len(self.edges)}")
