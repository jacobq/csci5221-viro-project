import traceback

import pox.openflow.libopenflow_01 as of
from pox.lib.packet import *
from pox.lib.addresses import *

from viro_veil import *

class ViroSwitch(object):
    def __init__(self, connection, transparent, viro_module):
        self.connection = connection
        self.transparent = transparent
        self.viro = viro_module
        self.dpid = viro_module.dpid
        self.vid = viro_module.vid
        self.round = 1
        self.demo_packet_sequence = self.generate_demo_packet_sequence()
        self.demo_sequence_number = 0

        # Statistics for performance / verification report
        self.switch_stats = {}
        for op_code, op_name in OP_NAMES.items():
            self.switch_stats[op_name] = {
                'sent': 0,
                'processed': 0,
                'received': 0
            }

        # When receiving VIRO data packets we can peek at the TTL
        # and determine the number of hops used since we know the
        # initial TTL
        for field in ['total_hops', 'originated', 'consumed', 'ttl_expired']:
            self.switch_stats['VIRO_DATA_OP'][field] = 0

        # We want to hear PacketIn messages, so we listen
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """

        packet = event.parsed
        match = of.ofp_match.from_packet(packet)
        # matching the packet type
        # print "OpenFlow (Ethernet) packet: ", packet
        try:
            if match.dl_type == packet.VIRO_TYPE:

                payload = packet.payload
                my_packet = payload
                [packet_type] = struct.unpack("!H", my_packet[6:8])

                if (packet_type == VIRO_CONTROL):
                    self.process_viro_packet(my_packet, match, event)  # handling the VIRO REQUEST
                    op_code = get_operation(my_packet)
                    self.switch_stats[get_operation_name(op_code)]['received'] += 1
                    return
                else:
                    print  "Ignoring packet since packet_type was not VIRO_CONTROL"
        except Exception:
            print "Error while processing packet"
            print traceback.format_exc()

    # Print messages in log when port status changed
    # (i.e. when administratively up/down)
    # See https://openflow.stanford.edu/display/ONL/POX+Wiki#POXWiki-PortStatus
    def _handle_PortStatus (self, event):
        if event.added:
            action = "added"
        elif event.deleted:
            action = "removed"
        else:
            action = "modified"
        print "Port %s on (switch %s) has been %s." % (event.port, event.dpid, action)

    def process_viro_packet(self, packet, match=None, event=None):
        L = len(self.vid)
        # print_packet(packet, L, True)
        dpid_length = get_dpid_length(self.dpid)

        op_code = get_operation(packet)
        self.switch_stats[get_operation_name(op_code)]['processed'] += 1

        if op_code == OP_CODES['DISCOVERY_ECHO_REQUEST']:
            packet_fields = decode_discovery_packet(packet, L, dpid_length)
            neighbor_vid = packet_fields['sender_vid']
            print "Neighbor discovery request message received from: ", neighbor_vid

            # Reply
            viro_packet = create_DISCOVER_ECHO_REPLY(self.vid, self.dpid)
            msg = self.create_openflow_message(of.OFPP_IN_PORT, FAKE_SRC_MAC, viro_packet, event.port)
            self.connection.send(msg)
            # print "Neighbor discovery reply message sent"

        elif op_code == OP_CODES['DISCOVERY_ECHO_REPLY']:
            packet_fields = decode_discovery_packet(packet, L, dpid_length)
            neighbor_vid = packet_fields['sender_vid']
            neighbor_port = event.port
            print "Neighbor discovery reply message received from vid: ", neighbor_vid, "port:", neighbor_port

            # Update routing table with this (possibly new) neighbors
            self.viro.update_routing_table_based_on_neighbor(neighbor_vid, neighbor_port)

        else:
            dst_vid = get_dest(packet, L)
            src_vid = get_src(packet, L)

            # forward the packet if it's not for us
            if dst_vid != self.vid:
                self.route_viro_packet(packet)
                return

            if op_code == OP_CODES['RDV_QUERY']:
                print "RDV_QUERY message received"
                rvdReplyPacket = self.viro.process_rdv_query(packet)
                if rvdReplyPacket == '':
                    return

                if src_vid == self.vid:
                    print "(processing my own RDV_REPLY)"
                    self.viro.process_rdv_reply(rvdReplyPacket)
                else:
                    msg = self.create_openflow_message(of.OFPP_IN_PORT, FAKE_SRC_MAC, rvdReplyPacket, event.port)
                    self.connection.send(msg)

                print "RDV_REPLY message sent"

            elif op_code == OP_CODES['RDV_PUBLISH']:
                self.viro.process_rdv_publish(packet)

            elif op_code == OP_CODES['RDV_REPLY']:
                self.viro.process_rdv_reply(packet)

            elif op_code == OP_CODES['VIRO_DATA_OP']:
                # The part where it handles VIRO data packet (by printing it then dropping it)
                contents = decode_viro_data_packet_contents(packet, L)
                print "Received a VIRO data packet:", contents
                stats = self.switch_stats['VIRO_DATA_OP']
                self.switch_stats['VIRO_DATA_OP']['consumed'] += 1
                self.switch_stats['VIRO_DATA_OP']['total_hops'] += MAX_TTL - contents['ttl']

                # Send reply back
                if self.vid == '0000':
                    print "(not replying to data packet since we are node 0000)"
                else:
                    print "Sending VIRO data reply"
                    src_vid = self.vid
                    dst_vid = contents['src_vid']
                    payload = ones_complement_str(contents['payload'])
                    reply_packet = create_VIRO_DATA(src_vid, dst_vid, src_vid, MAX_TTL, payload)
                    self.process_viro_packet(reply_packet)
                    self.switch_stats['VIRO_DATA_OP']['originated'] += 1

    def create_openflow_message(self, openflow_port, mac, packet, event_port=None):
        # Track statistics on sent messages
        # (assume that any message created using this function will be immediately sent)
        op_code = get_operation(packet)
        self.switch_stats[get_operation_name(op_code)]['sent'] += 1

        # encapsulating the VIRO packet into an ethernet frame
        # dst MAC defaults to ETHER_ANY = 00:00:00:00:00:00
        # (currently that's the same as VEIL_MASTER_MAC)
        e = ethernet(type=VIRO_DATA, src=EthAddr(mac), dst=EthAddr(VEIL_MASTER_MAC))
        e.set_payload(packet)

        # composing openFlow message
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        # send the message to the same port as the openflow port
        msg.actions.append(of.ofp_action_output(port=openflow_port))

        if (event_port is not None):
            msg.in_port = event_port
        return msg

    def start_round(self):
        print "vid", self.vid, 'starting round: ', self.round
        self.run_round(self.round)
        # Advance to next round (for next time), if not already at final round (L)
        L = len(self.vid)
        self.round += 1
        if self.round > L:
            self.round = L

        self.viro.print_routing_table()

    def run_round(self, round):
        routing_table = self.viro.routing_table
        L = len(self.vid)

        # start from round 2 since connectivity in round 1 is already learnt using the physical neighbors
        for k in range(2, round + 1):
            if not k in routing_table:
                routing_table[k] = []
            # publish ourself as a gateway to our physical neighbors
            for entry in routing_table[k]:
                if entry['gateway'] == int(self.vid, 2):
                    print "Sending RDV_PUBLISH for k =", k
                    packet, dst = self.viro.publish(entry, k)
                    self.route_viro_packet(packet)

            # If we don't yet have the maximum number of gateways / entries in our routing table, query for more
            if len(routing_table[k]) < MAX_GW_PER_LEVEL:
                print "Sending RDV_QUERY for k =", k
                packet, dst = self.viro.query(k)
                self.route_viro_packet(packet)

    # This function runs during initialization and just serves to generate
    # a set of VIDs that will be used for sending sample data packets for routing demonstration
    def generate_demo_packet_sequence(self):
        vid_sequence = []
        # Just generate sample data from 0000 to 1111
        if self.vid == '0000':
            vid_sequence.append('1111')
        return vid_sequence

    # This function gets called periodically by a timer
    # It simply steps through a sequence of destination VIDs, sending a message to another one
    # each time it is executed. The payload is just a rolling 32-bit counter value
    # that doesn't have any meaning in this simple demonstration except to distinguish / identify it
    # it in the switches log messages.
    def send_sample_viro_data(self):
        try:
            if len(self.demo_packet_sequence) < 1:
                # print "(not configured to send any sample packets)"
                return
            src_vid = self.vid
            dst_vid = self.demo_packet_sequence[self.demo_sequence_number % len(self.demo_packet_sequence)]
            # Start with our own VID as the forwarding directive and let the routing function
            # select an appropriate forwarding directive
            fwd_vid = src_vid
            self.demo_sequence_number += 1
            payload = bin(self.demo_sequence_number % 2**32).replace("0b", "")
            print "Sending sample VIRO data packet to", dst_vid, "with payload", payload
            packet = create_VIRO_DATA(src_vid, dst_vid, fwd_vid, MAX_TTL, payload)
            self.process_viro_packet(packet)
            self.switch_stats['VIRO_DATA_OP']['originated'] += 1
        except:
            print "ERROR: send_sample_viro_data encountered exception"
            print traceback.format_exc()

    # If this packet is destined for us then process it.
    # Otherwise, if it's a "data packet" then route it using multi-path routing.
    # Otherwise use the single-path routing algorithm provided since
    # the packet doesn't have the forwarding directive field in its header.
    # (We could update the packet format for these or encapsulate them into data packets,
    # but this is not necessary for this assignment.)
    def route_viro_packet(self, packet):
        L = len(self.vid)
        dst = get_dest(packet, L)
        if (dst == self.vid):
            # Packet is for this node, so consume it rather than forward it
            print 'I am the destination!'
            self.process_viro_packet(packet)
            return

        op_code = get_operation(packet)
        if op_code == OP_CODES['VIRO_DATA_OP']:
            self.route_viro_packet_via_forwarding_directive(packet)
        else:
            print "Using single-path routing for", get_operation_name(op_code), "packet"
            self.route_viro_packet_via_default_path(packet)

    def route_viro_packet_via_forwarding_directive(self, packet):
        packet_fields = decode_viro_data_packet_contents(packet, L)
        # print "Routing VIRO data packet:", packet_fields
        ttl = packet_fields['ttl']
        if ttl < 1:
            print "TTL expired: dropping data packet"
            self.switch_stats['VIRO_DATA_OP']['ttl_expired'] += 1
            return
        # Decrease the TTL to ensure that the packet won't get stuck forever in a routing loop
        ttl -= 1

        dst_vid = packet_fields['dst_vid']
        fwd_vid = packet_fields['fwd_vid']
        if fwd_vid == self.vid:
            # We are the node that the sender selected in its forwarding directive
            # so now we need to select a new gateway to use instead.
            # Since we look through the routing table to pick a random gateway we go ahead
            # and grab the next hop and port rather than looking them up
            fwd_vid, next_hop, port = self.viro.choose_gateway_for_forwarding_directive(dst_vid)
        else:
            # Don't need to change forwarding directive, but do need to find next hop from routing table
            # for the forwarding directive that was already specified
            next_hop, port = self.viro.get_next_hop(dst_vid)

        # Now send the packet to the next hop associated with the VID in the forwarding directive
        if next_hop is not None:
            # We could just modify the field in the original packet then send but
            # since the packed format makes that inconvenient here
            # we just create a new packet with the updated values instead.
            src_vid = packet_fields['src_vid']
            payload = packet_fields['payload']
            packet = create_VIRO_DATA(src_vid, dst_vid, fwd_vid, ttl, payload)
            self.send_packet_out_port(packet, port)
        else:
            print "No next hop found, so cannot route packet (using forwarding directive)"

    def route_viro_packet_via_default_path(self, packet):
        # get next_hop and port
        dst_vid = get_dest(packet, L)
        op_code = get_operation(packet)
        is_query_or_publish = op_code == OP_CODES['RDV_PUBLISH'] or op_code == OP_CODES['RDV_QUERY']
        next_hop, port = self.viro.get_next_hop(dst_vid, is_query_or_publish)
        if next_hop is not None:
            self.send_packet_out_port(packet, port)
        else:
            print "No next hop found, so cannot route packet (using default/single path)"

    def send_packet_out_port(self, packet, port):
        msg = self.create_openflow_message(of.OFPP_IN_PORT, FAKE_SRC_MAC, packet, int(port))
        self.connection.send(msg)

    # Called periodically for performance | debugging information
    def print_switch_stats(self):
        try:
            print '\n---- Statistics for:', self.vid, '|', self.dpid, ' ----'
            # Sort operations
            stats_items = self.switch_stats.items()
            stats_items.sort(key=lambda x: x[0])
            for op_name, stats in stats_items:
                print op_name
                for stat_name, stat_value in stats.items():
                    if stat_name == "total_hops":
                        consumed = stats['consumed']
                        if consumed > 0:
                            print "    average_hops:", stat_value/consumed
                    else:
                        print "    %s: %s" % (stat_name, stat_value)
            print '\n'
        except:
            print "ERROR: caught exception while trying to print switch statistics"
            print traceback.format_exc()
