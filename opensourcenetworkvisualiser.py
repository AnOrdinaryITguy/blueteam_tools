#Goals
# Replay a pcap in packet order and visualise it:
# Mark rare paths between targets -ML/Anomali?
# Mark rare Protocols  -ML/Anomali?
# Have a button to filter through Layers? might be hard but super cool
import networkx as nx
import matplotlib.pyplot as plt
import pyshark


# Ingest the PCAP
PacketCapture = pyshark.FileCapture('testing.pcapng')

## Visiualization section

# Create a graph
L3_PacketGraph = nx.DiGraph()
L4_PacketGraph = nx.DiGraph()

fig, (L3_title, L4_title) = plt.subplots(1, 2, figsize=(12, 7))
L3_title.set_title('Layer 3', loc='left')
L4_title.set_title('Layer 4', loc='left')

for Packet in PacketCapture:
    if 'eth' in Packet:
        # Add nodes for each Packet
        L3_PacketGraph.add_node(Packet['eth'].src, color='blue')
        L3_PacketGraph.add_node(Packet['eth'].dst, color='blue')
        # Connect the nodes
        L3_PacketGraph.add_edge(Packet['eth'].src, Packet['eth'].dst)
    if 'ip' in Packet:
        #Checking TCP and UDP ports
        if hasattr(Packet, 'tcp'):
            print('TCP '+Packet['ip'].src+':'+Packet.tcp.srcport+' -> '+Packet['ip'].dst+':'+Packet.tcp.dstport)
            if 1024 <= int(Packet.tcp.srcport) <= 49151 and 1024 <= int(Packet.tcp.dstport) <= 49151:
                TCPconvsource = Packet['ip'].src+':'+Packet.tcp.srcport
                TCPconvdest = Packet['ip'].dst+':'+Packet.tcp.dstport
                L4_PacketGraph.add_node(TCPconvsource, color='green')
                L4_PacketGraph.add_node(TCPconvdest, color='green')
                L4_PacketGraph.add_edge(TCPconvsource,TCPconvdest, label='tcp')
            else:
                TCPconvsource = Packet['ip'].src
                TCPconvdest = Packet['ip'].dst
                L4_PacketGraph.add_node(TCPconvsource, color='green')
                L4_PacketGraph.add_node(TCPconvdest, color='green')
                L4_PacketGraph.add_edge(TCPconvsource,TCPconvdest, label='tcp') #Should I add unregistered ports here?
        if hasattr(Packet, 'udp'):
            #Need to fix broadcast packets
            print('UDP '+Packet['ip'].src+':'+Packet.udp.srcport+' -> '+Packet['ip'].dst+':'+Packet.udp.dstport)
            if 1024 <= int(Packet.udp.srcport) <= 49151 and 1024 <= int(Packet.udp.dstport) <= 49151:
                UDPconvsource = Packet['ip'].src+':'+Packet.udp.srcport
                UDPconvdest = Packet['ip'].dst+':'+Packet.udp.dstport
                L4_PacketGraph.add_node(UDPconvsource, color='yellow')
                L4_PacketGraph.add_node(UDPconvdest, color='yellow')
                L4_PacketGraph.add_edge(UDPconvsource,UDPconvdest, label='udp')
            else:
                UDPconvsource = Packet['ip'].src
                UDPconvdest = Packet['ip'].dst
                L4_PacketGraph.add_node(UDPconvsource, color='yellow')
                L4_PacketGraph.add_node(UDPconvdest, color='yellow')
                L4_PacketGraph.add_edge(UDPconvsource,UDPconvdest, label='udp') #Should I add unregistered ports here?


# L3 graph
# Changing the size of nodes depending on the amount of occurences
L3_occurrences = {}
for edge in L3_PacketGraph.edges():
    for node in edge:
        L3_occurrences[node] = L3_occurrences.get(node, 0) + 1
L3_node_sizes = [L3_occurrences.get(node, 1) * 100 for node in L3_PacketGraph.nodes()]

# Draw the graph using Matplotlib
pos = nx.spring_layout(L3_PacketGraph)  # positions for all nodes
node_colors = [L3_PacketGraph.nodes[node]['color'] for node in L3_PacketGraph.nodes()]

# Drawing all the stuff
nx.draw_networkx_nodes(L3_PacketGraph, pos, node_size=L3_node_sizes, node_color=node_colors, ax=L3_title)
nx.draw_networkx_edges(L3_PacketGraph, pos, arrows=True, ax=L3_title)
nx.draw_networkx_labels(L3_PacketGraph, pos, ax=L3_title)

### L4 graph ###
# Changing the size of nodes depending on the amount of occurences
L4_occurrences = {}
for edge in L4_PacketGraph.edges():
    for node in edge:
        L4_occurrences[node] = L4_occurrences.get(node, 0) + 1
L4_node_sizes = [L4_occurrences.get(node, 1) * 100 for node in L4_PacketGraph.nodes()]

# L4 graph
# Draw the graph using Matplotlib
pos = nx.spring_layout(L4_PacketGraph)  # positions for all nodes
node_colors = [L4_PacketGraph.nodes[node]['color'] for node in L4_PacketGraph.nodes()]
edge_labels = nx.get_edge_attributes(L4_PacketGraph, 'label')

# Drawing all the stuff
nx.draw_networkx_nodes(L4_PacketGraph, pos, node_size=L4_node_sizes, node_color=node_colors, ax=L4_title)
nx.draw_networkx_edges(L4_PacketGraph, pos, arrows=True, ax=L4_title)
nx.draw_networkx_labels(L4_PacketGraph, pos, ax=L4_title)
nx.draw_networkx_edge_labels(L4_PacketGraph, pos, edge_labels=edge_labels, font_color='black')

plt.show()
