#generic imports
import sys
import os
import random
import time
import traceback
import csv

#pox-specific imports
from pox.core import core
from pox.openflow import ethernet
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.revent import *
from pox.lib.recoco import Timer

#networkx import for graph management
import networkx as nx # this is for graph creation 
#for beautiful prints of dicts, lists, etc,
from pprint import pprint as pp

log = core.getLogger()

MAX_PHYS_PORTS = 0xFF00


class CloudNetController (EventMixin):

	_neededComponents = set(['openflow_discovery'])

	def __init__(self, firewall_capability, migration_capability, firewall_policy_file, migration_events_file):
		super(EventMixin, self).__init__()

		#generic controller information
		self.switches = {}	   # key=dpid, value = SwitchWithPaths instance
		self.sw_sw_ports = {}  # key = (dpid1,dpid2), value = outport of dpid1
		self.adjs = {}		   # key = dpid, value = list of neighbors
		self.arpmap = {} # key=host IP, value = (mac,dpid,port)
		self._paths_computed = False #boolean to indicate if all paths are computed (converged routing)
		self.ignored_IPs = [IPAddr("0.0.0.0"), IPAddr("255.255.255.255")] #these are used by openflow discovery module

		#invoke event listeners
		if not core.listen_to_dependencies(self, self._neededComponents):
			self.listenTo(core)
		self.listenTo(core.openflow)

		#module-specific information
		self.firewall_capability = firewall_capability
		self.migration_capability = migration_capability
		self.firewall_policies = None
		self.migration_events = None
		self.migrated_IPs = None
		if self.firewall_capability:
			self.firewall_policies = self.read_firewall_policies(firewall_policy_file)
		if self.migration_capability:
			self.migration_events = self.read_migration_events(migration_events_file)
			self.old_migrated_IPs = {} #key=old_IP, value=new_IP
			self.new_migrated_IPs = {} #key=new_IP, value=old_IP
			for event in self.migration_events:
				migration_time = event[0]
				old_IP = event[1]
				new_IP = event[2]
				Timer(migration_time, self.handle_migration, args = [IPAddr(old_IP), IPAddr(new_IP)])

	def read_firewall_policies(self, firewall_policy_file):
		firewall_policies = {}
		with open(firewall_policy_file, 'r') as csvfile:
			reader = csv.reader(csvfile)
			for row in reader:
				tenant_id = row[0]
				for ip in row[1:len(row)]:
					firewall_policies[IPAddr(ip)] = int(tenant_id)
		return firewall_policies

	def read_migration_events(self, migration_info_file):
		migration_events = []
		with open(migration_info_file, 'r') as csvfile:
			reader = csv.reader(csvfile)
			for row in reader:
				migration_time = int(row[0])
				old_ip = IPAddr(row[1])
				new_ip = IPAddr(row[2])
				migration_events.append((migration_time, old_ip, new_ip))
		return migration_events

	def _handle_ConnectionUp(self, event):
		if event.dpid not in self.switches:
			self.switches[event.dpid] = SwitchWithPaths()
			if event.dpid not in self.adjs:
				self.adjs[event.dpid] = set([])
		self.switches[event.dpid].connect(event.connection)
		#send unknown ARP and IP packets to controller (install rules for that with low priority)
		msg_ARP = of.ofp_flow_mod()
		msg_IP	= of.ofp_flow_mod()
		msg_ARP.match.dl_type = 0x0806
		msg_IP.match.dl_type  = 0x0800
		msg_ARP.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
		msg_IP.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
		msg_ARP.priority = of.OFP_DEFAULT_PRIORITY - 1
		msg_IP.priority	 = of.OFP_DEFAULT_PRIORITY - 1
		event.connection.send(msg_ARP)
		event.connection.send(msg_IP)

	def _handle_ConnectionDown(self, event):
		ips_to_forget = []
		for ip in self.arpmap:
			(mac, dpid, port) = self.arpmap[ip]
			if dpid == event.dpid:
				ips_to_forget.append(ip)
		for ip in ips_to_forget:
			del self.arpmap[ip]
		if (event.dpid in self.switches):
			self.switches[event.dpid].disconnect()
			del self.switches[event.dpid]
		#let the discovery module deal with the port removals...

	def flood_on_all_switch_edges(self, packet, this_dpid, this_port):
		for src_dpid in self.switches:
			no_flood_ports = set([]) #list of non-flood ports
			if src_dpid in self.adjs:
				for nei_dpid in self.adjs[src_dpid]:
					no_flood_ports.add(self.sw_sw_ports[(src_dpid,nei_dpid)])
			if src_dpid == this_dpid:
				no_flood_ports.add(this_port)
			self.switches[src_dpid].flood_on_switch_edge(packet, no_flood_ports)

	def update_learned_arp_info(self, packet, dpid, port):
		src_ip = None
		src_mac = None
		if packet.type == packet.ARP_TYPE:
			src_mac = EthAddr(packet.src)
			src_ip	= IPAddr(packet.next.protosrc)
		elif packet.type == packet.IP_TYPE:
			src_mac = EthAddr(packet.src)
			src_ip	= IPAddr(packet.next.srcip)
		else:
			pass
		if (src_ip != None) and (src_mac != None):
			self.arpmap[src_ip] = (src_mac, dpid, port)

	def _handle_PacketIn(self, event):
		packet = event.parsed
		dpid = event.dpid
		inport = event.port

		def handle_ARP_pktin():
			srcip = IPAddr(packet.next.protosrc)
			dstip = IPAddr(packet.next.protodst)
			if (srcip in self.ignored_IPs) or (dstip in self.ignored_IPs):
				return

			if packet.next.opcode == arp.REQUEST:
				log.info("Handling ARP packet: %s requests the MAC of %s" % (str(srcip), str(dstip)))
				self.update_learned_arp_info(packet, dpid, inport)

				#FIREWALL functionality
				if self.firewall_capability:
					try:
						if self.firewall_policies[srcip]!=self.firewall_policies[dstip]: #if value is not the same so it means that you are in the different row 
							self.drop_packets(dpid,packet)
							return
							
					except KeyError:
						log.info("IPs not covered by policy!")
						return

				if self.migration_capability:
					#ignore ARP requests coming from old migrated IPs or directed to new ones
					if (srcip in self.old_migrated_IPs) or (dstip in self.new_migrated_IPs):
						return

				if dstip in self.arpmap:
					log.info("I know where to send the crafted ARP reply!")
					(req_mac, req_dpid, req_port) = self.arpmap[dstip]
					(dst_mac, dst_dpid, dst_port) = self.arpmap[srcip]
					self.switches[dst_dpid].send_arp_reply(packet, dst_port, req_mac)
				else:
					log.info("Flooding initial ARP request on all switch edges")
					self.flood_on_all_switch_edges(packet, dpid, inport)

			elif packet.next.opcode == arp.REPLY:
				log.info("Handling ARP packet: %s responds to %s" % (str(srcip), str(dstip)))
				self.update_learned_arp_info(packet, dpid, inport)

				#FIREWALL functionality
				if self.firewall_capability:
					try:
						if self.firewall_policies[srcip]!=self.firewall_policies[dstip]: #if value is not the same so it means that you are in the different row 
							self.drop_packets(dpid,packet)
							return
							
					except KeyError:
						return

				if self.migration_capability:
					#ignore ARP replies coming from old migrated IPs or directed to new ones
					if (srcip in self.old_migrated_IPs) or (dstip in self.new_migrated_IPs):
						return

				if dstip in self.arpmap.keys():
					log.info("I know where to send the initial ARP reply!")
					(dst_mac, dst_dpid, dst_port) = self.arpmap[dstip]
					self.switches[dst_dpid].send_packet(dst_port, packet)
				else:
					log.info("Flooding initial ARP reply on all switch edges")
					self.flood_on_all_switch_edges(packet,dpid,inport)
			else:
				log.info("Unknown ARP type")
				return

		def handle_IP_pktin():
			srcip = IPAddr(packet.next.srcip)
			dstip = IPAddr(packet.next.dstip)
			if (srcip in self.ignored_IPs) or (dstip in self.ignored_IPs):
				return

			log.info("Handling IP packet between %s and %s" % (str(srcip), str(dstip)))

			#FIREWALL functionality
			if self.firewall_capability:
				try:
					if self.firewall_policies[srcip]!=self.firewall_policies[dstip]: #if value is not the same so it means that you are in the different row 
						self.drop_packets(dpid,packet)
						return
							
				except KeyError:
					log.info("IPs not covered by policy!")
					return

			if self._paths_computed:
				print "Routing calculations have converged"
				log.info("Path requested for flow %s-->%s" % (str(srcip), str(dstip)))

				if dstip in self.arpmap: #I know where to send the packet
					(dst_mac, dst_dpid, dst_port) = self.arpmap[dstip]

					#MIGRATION functionality
					if self.migration_capability:
						#IP packet goes to old server after migration is done
						if dstip in self.old_migrated_IPs:
							(dst_mac, dst_dpid, dst_port) = self.arpmap[self.old_migrated_IPs[dstip]]
							#install path to new server and change packet headers
							log.info("Installing migrated forward path towards: old IP: %s, new IP: %s" % (str(dstip), str(self.old_migrated_IPs[dstip])))
							self.install_migrated_end_to_end_IP_path(event, dst_dpid, dst_port, packet, forward_path=True)
							log.info("Forward migrated path installed")

						#IP packet comes from new server after migration is done
						elif srcip in self.new_migrated_IPs:
							(dst_mac, dst_dpid, dst_port) = self.arpmap[dstip]
							log.info("Installing migrated reverse path from: old IP: %s, new IP: %s" % (str(srcip), str(self.new_migrated_IPs[srcip])))
							self.install_migrated_end_to_end_IP_path(event, dst_dpid, dst_port, packet, forward_path=False)
							log.info("Reverse migrated path installed")
						else:
							self.install_end_to_end_IP_path(event, dst_dpid, dst_port, packet)
					else:
						self.install_end_to_end_IP_path(event, dst_dpid, dst_port, packet)
				else:
					self.flood_on_all_switch_edges(packet, dpid, inport)
			else:
				print "Routing calculations have not converged, discarding packet"
				return

		#--------------------------------------------------------------------------------------------------------------
		if packet.type == packet.LLDP_TYPE:
			return

		elif packet.type == packet.ARP_TYPE:
			handle_ARP_pktin()
			return

		elif packet.type == packet.IP_TYPE:
			handle_IP_pktin()
			return

		else:
			#log.info("Unknown Packet type: %s" % packet.type)
			return


	def install_end_to_end_IP_path(self, event, dst_dpid, final_port, packet):
		source_switch=event.dpid 						#take the switch node triggered the event
		dest_switch=dst_dpid 							#take the destination node switch
		random_path=random.choice(self.switches[source_switch]._paths[dest_switch]) #compute a random path between shortest selected

		length_path=len(random_path)-1 					# last path index
		length_random=len(random_path) 
		if source_switch==dest_switch:
														#means that we are in the same switch edge
			match=of.ofp_match()
			match.dl_type = ethernet.IP_TYPE
			match.nw_src=packet.next.srcip
			match.nw_dst=packet.next.dstip
			
			self.switches[source_switch].install_output_flow_rule(final_port, match) 	#install rule to the edge switch 
			self.switches[source_switch].send_packet(final_port, event.data) 											#send icmp packet
		else:
			for index in range(length_random): 		
				reverse_index=length_path-index #go to the last index 
				
				match=of.ofp_match()
				match.dl_type = ethernet.IP_TYPE
				match.nw_src=packet.next.srcip
				match.nw_dst=packet.next.dstip
				
				if(reverse_index!=length_path):
					outport = self.sw_sw_ports[(random_path[reverse_index],random_path[reverse_index+1])] #else if we are in the other switches 
				else:
					outport =final_port					#if we are in the last switch 
				
				self.switches[random_path[reverse_index]].install_output_flow_rule(outport, match)	#install rules in route
			self.switches[source_switch].send_packet(self.sw_sw_ports[(source_switch,random_path[1])], event.data)			# send the icmp packet 
		
	def install_migrated_end_to_end_IP_path(self, event, dst_dpid, dst_port, packet, forward_path=True):
		#SEND AN IP PACKET FROM H6 TO H1 
		#h1 will go inactive and h5 will serve it 
		#h6 will be source
		#h1 dest
		
		source_switch=event.dpid
		dest_switch=dst_dpid
		match=of.ofp_match()
		match.dl_type = ethernet.IP_TYPE
		match.nw_src=packet.next.srcip
		match.nw_dst=packet.next.dstip
		
		if(forward_path==True): #if ip packet goes to old server after migration, we have to forward(send it) it to the new
			inactive_host_ip=packet.next.dstip
			new_host_ip=self.old_migrated_IPs[inactive_host_ip] #match the inactive ip eith the one it would be migrated
			
			(dst_mac, dst_dpid, dst_port) = self.arpmap[new_host_ip] #take mac port and dpid of migrated host
			
			random_path=random.choice(self.switches[source_switch]._paths[dst_dpid]) #compute a random path between source switch and and new desst
			length_path=len(random_path)-1
			length_random=len(random_path)
			
			if(source_switch==dst_dpid): #if src and new dest are in the same neighboorhood
				self.switches[source_switch].install_forward_migration_rule(dst_port, dst_mac, new_host_ip, match, idle_timeout=0, hard_timeout=0)
				self.switches[source_switch].send_forward_migrated_packet(dst_port, dst_mac, new_host_ip, event.data)				
			else:
				for index in range(length_random):
					reverse_index=length_path-index #go to the last index of the random path
				
				if(reverse_index!=length_path): #check if is the last node to take the port
					if(reverse_index==0):		#if the edge node of source
						outport=self.sw_sw_ports[(source_switch,random_path[1])]
						self.switches[source_switch].install_forward_migration_rule(outport, dst_mac,new_host_ip, match)
						self.switches[source_switch].send_forward_migrated_packet(outport, dst_mac, new_host_ip,event.data)
					else:
						outport = self.sw_sw_ports[(random_path[reverse_index],random_path[reverse_index+1])]
						self.switches[random_path[reverse_index]].install_output_flow_rule(outport, match)
				else: 							#the last node
					outport =dst_port
					self.switches[random_path[reverse_index]].install_output_flow_rule(outport, match) 
		elif(forward_path==False):
												#h5 sould reply as h1 to the source
			source_ip=packet.next.srcip #h5 ip
			inactive_host_ip=self.new_migrated_IPs[source_ip] #h1
			(h1_mac, h1_dpid, h1_port) = self.arpmap[inactive_host_ip] # h1 mac port 
			
			random_path=random.choice(self.switches[source_switch]._paths[dst_dpid]) #compute a random path between new dest switch and and source
			length_path=len(random_path)-1
			length_random=len(random_path)
			
			if(source_switch==dst_dpid): #if src and new dest are in the same neighboorhood
				self.switches[source_switch].install_reverse_migration_rule(dst_port, h1_mac,inactive_host_ip, match, idle_timeout=0, hard_timeout=0)
				self.switches[source_switch].send_reverse_migrated_packet(dst_port, h1_mac, inactive_host_ip, event.data)				
			else:
				for index in range(length_random):
					reverse_index=length_path-index #go to the last index of the random path
				
					if(reverse_index!=length_path): #check if is the last node to take the port
						if(reverse_index==0):		#if the edge node of source
							outport=self.sw_sw_ports[(source_switch,random_path[1])]
							self.switches[source_switch].install_reverse_migration_rule(outport, h1_mac, inactive_host_ip, match)
							self.switches[source_switch].send_reverse_migrated_packet(outport, h1_mac, inactive_host_ip,event.data)
						else:
							outport = self.sw_sw_ports[(random_path[reverse_index],random_path[reverse_index+1])]
							self.switches[random_path[reverse_index]].install_output_flow_rule(outport, match,20)
					else: 							#the last node
						outport =dst_port
						self.switches[random_path[reverse_index]].install_output_flow_rule(outport, match,20) 
	def handle_migration(self, old_IP, new_IP):
		log.info("Handling migration from %s to %s..." % (str(old_IP), str(new_IP)))
		# create ofp_flow_mod message to delete all flows
		# to the destination to be migrated
		msg_1 = of.ofp_flow_mod()
		match_1 = of.ofp_match()
		match_1.dl_type = 0x0800
		match_1.nw_dst = old_IP
		msg_1.match = match_1
		msg_1.command = of.OFPFC_DELETE
		# create ofp_flow_mod message to delete all flows
		# coming from the source that will host the migrated one
		msg_2 = of.ofp_flow_mod()
		match_2 = of.ofp_match()
		match_2.dl_type = 0x0800
		match_2.nw_src = new_IP
		msg_2.match = match_2
		msg_2.command = of.OFPFC_DELETE
		# send the ofp_flow_mod messages to all switches
		# leading to the destination to be migrated (or coming from the source that will host it)
		for sw in self.switches:
			self.switches[sw].connection.send(msg_1)
			log.info("Rules having as dest %s removed at switch: %i" % (str(old_IP), sw))
			self.switches[sw].connection.send(msg_2)
			log.info("Rules having as source %s removed at switch: %i" % (str(new_IP), sw))
		log.info("Rules deleted, now new IP e2e paths will be automatically migrated to the new IP %s" % (str(new_IP)))
		self.old_migrated_IPs[old_IP] = new_IP
		self.new_migrated_IPs[new_IP] = old_IP
		(new_mac, new_dpid, new_inport) = self.arpmap[self.old_migrated_IPs[old_IP]]
		self.arpmap[old_IP] = (new_mac, new_dpid, new_inport)
		log.info("Arpmap for old ip updated")

	def drop_packets(self, dpid, packet):
		match = of.ofp_match.from_packet(packet)
		self.switches[dpid].install_drop_flow_rule(match, idle_timeout=0, hard_timeout=0)

	def _handle_openflow_discovery_LinkEvent(self, event):
		self._paths_computed = False
		link = event.link
		dpid1 = link.dpid1
		port1 = link.port1
		dpid2 = link.dpid2
		port2 = link.port2
		if dpid1 not in self.adjs:
			self.adjs[dpid1] = set([])
		if dpid2 not in self.adjs:
			self.adjs[dpid2] = set([])

		if event.added:
			self.sw_sw_ports[(dpid1,dpid2)] = port1
			self.sw_sw_ports[(dpid2,dpid1)] = port2
			self.adjs[dpid1].add(dpid2)
			self.adjs[dpid2].add(dpid1)
		else:
			if (dpid1,dpid2) in self.sw_sw_ports:
				del self.sw_sw_ports[(dpid1,dpid2)]
			if (dpid2,dpid1) in self.sw_sw_ports:
				del self.sw_sw_ports[(dpid2,dpid1)]
			if dpid2 in self.adjs[dpid1]:
				self.adjs[dpid1].remove(dpid2)
			if dpid1 in self.adjs[dpid2]:
				self.adjs[dpid2].remove(dpid1)

		#print "Current switch-to-switch ports:"
		#pp(self.sw_sw_ports)
		#print "Current adjacencies:"
		#pp(self.adjs)
		self._paths_computed=False
		self.checkPaths()
		if self._paths_computed == False:
			print "Warning: Disjoint topology, Shortest Path Routing converging"
		else:
			#print "Topology connected, Shortest paths (re)computed successfully, Routing converged"
			#print "--------------------------"
			for dpid in self.switches:
				self.switches[dpid].printPaths()
			print "--------------------------"

	def checkPaths(self):
		if not self._paths_computed:
			self._paths_computed = ShortestPaths(self.switches, self.adjs)
		return self._paths_computed

	def __str__(self):
		return "Cloud Network Controller"


class SwitchWithPaths (EventMixin):
	def __init__(self):
		self.connection = None
		self.dpid = None
		self.ports = None
		self._listeners = None
		self._paths = {}

	def __repr__(self):
		return dpidToStr(self.dpid)

	def appendPaths(self, dst, paths_list):
		if dst not in self._paths:
			self._paths[dst] = []
		self._paths[dst] = paths_list

	def clearPaths(self):
		self._paths = {}

	def printPaths(self):
		"""for dst in self._paths:
			equal_paths_number = len(self._paths[dst])
			if equal_paths_number > 1:
				print "There are %i shortest paths from switch %i to switch %i:" % (equal_paths_number, self.dpid, dst)
			else:
				print "There is exactly one shortest path from switch %i to switch %i:" % (self.dpid, dst)
			for path_index in range(0, equal_paths_number):
				for u in self._paths[dst][path_index]:
					 print "%i," % (u),
				print"""

	def connect(self, connection):
		if self.dpid is None:
			self.dpid = connection.dpid
		assert(self.dpid == connection.dpid)
		if self.ports is None:
			self.ports = connection.features.ports
		log.info("Connect %s" % (connection))
		self.connection = connection
		self._listeners = self.listenTo(connection)

	def disconnect(self):
		if self.connection is not None:
			log.info("Disconnect %s" % (self.connection))
			self.connection.removeListeners(self._listeners)
			self.connection = None
			self._listeners = None

	def flood_on_switch_edge(self, packet, no_flood_ports):
		for no_flood in self.ports: 		#flood arp req in all ports to know mac and ip adress	
			if no_flood.port_no not in no_flood_ports and no_flood.port_no!=65534:
				self.send_packet(no_flood.port_no,packet)

	def send_packet(self, outport, packet_data=None):
		msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
		msg.data = packet_data
		msg.actions.append(of.ofp_action_output(port=outport))
		self.connection.send(msg)

	def send_arp_reply(self, packet, dst_port, req_mac):
		r=arp();
		r.hwtype = r.HW_TYPE_ETHERNET 	#type of hardware tyr
		r.prototype = r.PROTO_TYPE_IP 	#protocolo type
		r.hwlen = 6  					#hardware addrese length 6 bytes and mac=ipv6 
		r.protolen = r.protolen 		#the ipv4 length 
		r.opcode = r.REPLY				# the packet has Reply type 

		r.hwdst = packet.payload.hwsrc  
		r.hwsrc =req_mac				#fake mac
		
											#Reverse the src , dest to have an answer 
		r.protosrc = packet.payload.protodst 
		r.protodst = packet.payload.protosrc

		e = ethernet(type=packet.ARP_TYPE, src=req_mac, dst=packet.payload.hwsrc)
		e.set_payload(r)
		
		msg = of.ofp_packet_out()
		msg.data = e.pack()
									#send the message through the client outport 
		msg.actions.append(of.ofp_action_output(port =of.OFPP_IN_PORT)) # in which port clients can hear 
		msg.in_port = dst_port
		self.connection.send(msg)

	def install_output_flow_rule(self, outport, match, idle_timeout=0, hard_timeout=0):
		msg=of.ofp_flow_mod()
		msg.match = match
		msg.command = of.OFPFC_MODIFY_STRICT
		msg.idle_timeout = idle_timeout
		msg.hard_timeout = hard_timeout
		msg.actions.append(of.ofp_action_output(port=outport))
		self.connection.send(msg)

	def install_drop_flow_rule(self, match, idle_timeout=0, hard_timeout=0):
		msg=of.ofp_flow_mod()
		msg.match = match
		msg.command = of.OFPFC_MODIFY_STRICT
		msg.idle_timeout = idle_timeout
		msg.hard_timeout = hard_timeout
		msg.actions = [] #empty action list for dropping packets
		self.connection.send(msg)

	def send_forward_migrated_packet(self, outport, dst_mac, dst_ip, packet_data=None):
		"""
		when h1 have to send a packet it has to seem like h5"""
		
		msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
		msg.data = packet_data
		msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
		msg.actions.append(of.ofp_action_nw_addr.set_dst(dst_ip))
		msg.actions.append(of.ofp_action_output(port=outport))
		self.connection.send(msg)


	def send_reverse_migrated_packet(self, outport, src_mac, src_ip, packet_data=None):
		#h5 will respond as h1
		
		msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
		msg.data = packet_data
		msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
		msg.actions.append(of.ofp_action_nw_addr.set_src(src_ip))
		msg.actions.append(of.ofp_action_output(port=outport))
		self.connection.send(msg)
		
	def install_forward_migration_rule(self, outport, dst_mac, dst_ip, match, idle_timeout=0, hard_timeout=0):
		msg=of.ofp_flow_mod()
		msg.match = match
		msg.command = of.OFPFC_MODIFY_STRICT
		msg.idle_timeout = idle_timeout
		msg.hard_timeout = hard_timeout
		
		msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
		msg.actions.append(of.ofp_action_nw_addr.set_dst(dst_ip))
		msg.actions.append(of.ofp_action_output(port=outport))
		self.connection.send(msg)
	def install_reverse_migration_rule(self, outport, src_mac, src_ip, match, idle_timeout=0, hard_timeout=0):
		msg=of.ofp_flow_mod()
		msg.match = match
		msg.command = of.OFPFC_MODIFY_STRICT
		msg.idle_timeout = idle_timeout
		msg.hard_timeout = hard_timeout
		
		msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
		msg.actions.append(of.ofp_action_nw_addr.set_src(src_ip))
		msg.actions.append(of.ofp_action_output(port=outport))
		self.connection.send(msg)

def ShortestPaths(switches, adjs):
	#Create the graph for each switch and link them
	graph=nx.DiGraph()
	
	for adj in adjs: 				# take nodes 
		graph.add_node(adj) 		# take link to nodes 
		for links in adjs.get(adj):
			graph.add_edge(adj,links)
	#go to the dictionary where switches are stored and compute the shortest path 		
	try:
		for node in switches:
			for adj in switches:
				switches[node].appendPaths(adj,list(nx.all_shortest_paths(graph,node,adj)))
			
	except: nx.NetworkXNoPath
	
	return True		
	
def str_to_bool(str):
	assert(str in ['True', 'False'])
	if str=='True':
		return True
	else:
		return False

		
def launch(firewall_capability='True', migration_capability='True',
		   firewall_policy_file='./ext/firewall_policies.csv', migration_events_file='./ext/migration_events.csv'):
	"""
	Args:
		firewall_capability	 : boolean, True/False
		migration_capability : boolean, True/False
		firewall_policy_file : string, filename of the csv file with firewall policies
		migration_info_file	 : string, filename of the csv file with migration information
	"""
	log.info("Loading Cloud Network Controller")
	firewall_capability = str_to_bool(firewall_capability)
	log.info("Firewall Capability enabled: %s" % (firewall_capability))
	migration_capability = str_to_bool(migration_capability)
	log.info("Migration Capability enabled: %s" % (migration_capability))
	core.registerNew(CloudNetController, firewall_capability, migration_capability, firewall_policy_file, migration_events_file)
	log.info("Network Controller loaded")