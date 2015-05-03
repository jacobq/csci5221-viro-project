import time
import sys

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.packet import *
from pox.lib.addresses import *
from pox.lib.util import *
from pox.lib.recoco import Timer

from viro_module import ViroModule
from viro_constant import *
from viro_veil import *



class ViroSwitch(object):
    def __init__(self, connection, transparent, viro_module):

        self.connection = connection
        self.transparent = transparent
        self.viro = viro_module
        self.dpid = viro_module.dpid
        self.vid = viro_module.vid
        self.round = 1

        # We want to hear PacketIn messages, so we listen
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """

        packet = event.parsed
        match = of.ofp_match.from_packet(packet)
        # matching the packet type
        try:
            if (match.dl_type == packet.VIRO_TYPE ):

                print  "VIRO packet received....."
                payload = packet.payload
                my_packet = payload
                [packet_type] = struct.unpack("!H", my_packet[6:8])

                if (packet_type == VIRO_CONTROL):
                    self.process_viro_packet(my_packet, match, event)  # handling the VIRO REQUEST
                    return
        except:
            print "Error while processing packet"


    def process_viro_packet(self, packet, match=None, event=None):
        L = len(self.vid)
        length = get_dpid_length(self.dpid)

        op_code = get_op_code(packet)

        if op_code == DISCOVERY_ECHO_REQUEST:
            packet_fields = print_discover_packet(packet, L, length)  # gets the fields from the packet
            neighbor_vid = packet_fields[1]

            print "Neighbor discovery request message received from: ", neighbor_vid
            r = create_DISCOVER_ECHO_REPLY(self.vid, self.dpid)
            mac = FAKE_MAC
            msg = self.create_openflow_message(of.OFPP_IN_PORT, mac, r, event.port)
            self.connection.send(msg)
            print "Neighbor discovery reply message sent"


        elif op_code == DISCOVERY_ECHO_REPLY:
            packet_fields = print_discover_packet(packet, L, length)  # gets the fields from the packet
            neighbor_vid = packet_fields[1]
            neighbor_port = event.port
            print "Neighbor discovery reply message received from: ", neighbor_vid
            self.viro.update_routing_table_based_on_neighbor(neighbor_vid, neighbor_port)

        else:
            # print_packet(packet, L)
            dst_vid = get_dest(packet, L)  # gets the packet dst_vid
            src_vid = get_src(packet, L)  # gets the packet src_vid

            # forward the packet if I am not the destination
            if dst_vid != self.vid:
                self.route_viro_packet(packet)
                return

            if op_code == RDV_QUERY:
                print "RDV_QUERY message received"
                if src_vid == self.vid:
                    print "I am the rdv point - processing the packet"
                    self.viro.process_self_rvd_query(packet)
                    return

                else:
                    rvdReplyPacket = self.viro.process_rvd_query(packet)

                    if (rvdReplyPacket == ''):
                        return

                    mac = FAKE_MAC
                    msg = self.create_openflow_message(of.OFPP_IN_PORT, mac, rvdReplyPacket, event.port)

                    self.connection.send(msg)
                    print "RDV_REPLY message sent"


            elif op_code == RDV_PUBLISH:
                self.viro.process_rdv_publish(packet)


            elif op_code == RDV_REPLY:

                print "RDV_REPLY message received"
                self.viro.process_rdv_reply(packet)

            elif op_code == VIRO_DATA_OP:
                # The part where it handles VIRO data packet
                print "Received a VIRO Data Packet"


    def create_openflow_message(self, openflow_port, mac, packet, event_port=None):
        # encapsulating the VIRO packet into an ethernet frame
        e = ethernet(type=0x0802, src=EthAddr(mac))
        e.set_payload(packet)

        # composing openFlow message
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(
            of.ofp_action_output(port=openflow_port))  # send the message to the same port as the openflow port

        if (event_port != None):
            msg.in_port = event_port
        return msg


    def start_round(self):
        print self.vid, 'Starting Round : ', self.round

        self.run_round(self.round)

        # Advance to next round, if not already at final round (L)
        L = len(self.vid)
        self.round += 1
        if self.round > L:
            self.round = L

        self.viro.print_routing_table()


    def run_round(self, round):
        routing_table = self.viro.routing_table
        L = len(self.vid)

        # start from round 2 since connectivity in round 1 is already learnt using the physical neighbors
        for i in range(2, round + 1):
            # see if routing entry for this round is already available in the routing table.
            if i in routing_table and len(routing_table[i]) > 0:
                # publish the information if it is already there
                for entry in routing_table[i]:
                    if entry['gateway'] == int(self.vid, 2):
                        print "Sending rdv publish messages"
                        packet, dst = self.viro.publish(entry, i)
                        self.route_viro_packet(packet)
            else:
                print "Sending rdv query messages"
                packet, dst = self.viro.query(i)
                self.route_viro_packet(packet)


    def route_viro_packet(self, packet):
        # Type of packet: rvds Query or Publish
        # k - bucket level


        L = len(self.vid)
        dst = get_dest(packet, L)

        # If it's me
        if (dst == self.vid):
            print 'I am the destination!'
            self.process_viro_packet(packet)
            return

        # get next_hop and port
        next_hop, port = self.viro.get_next_hop(packet)
        if (next_hop != ''):
            dst_dpid = FAKE_MAC
            msg = self.create_openflow_message(of.OFPP_IN_PORT, dst_dpid, packet, int(port))
            self.connection.send(msg)
        else:
            print " Next hop is none "
