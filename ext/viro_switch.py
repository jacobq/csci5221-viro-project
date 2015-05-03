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
                mypacket = payload
                [packetType] = struct.unpack("!H", mypacket[6:8])

                if (packetType == VIRO_CONTROL):
                    self.process_viro_packet(mypacket, match, event)  # handling the VIRO REQUEST
                    return
        except:
            print "Error while processing packet"


    def process_viro_packet(self, packet, match=None, event=None):
        L = len(self.vid)
        length = getdpidLength(self.dpid)

        op_code = getopcode(packet)

        if op_code == DISC_ECHO_REQ:  # Handles the echo neibghour discover message/packet
            # sends a disc_echo_reply packet

            packet_fields = printDiscoverPacket(packet, L, length)  # gets the fields from the packet
            neighbor_vid = packet_fields[1]

            print "Neighbor discovery request message received from: ", neighbor_vid
            r = createDISCOVER_ECHO_REPLY(self.vid, self.dpid)
            mac = FAKE_MAC
            msg = self.create_openflow_message(of.OFPP_IN_PORT, mac, r, event.port)
            self.connection.send(msg)
            print "Neighbor discovery reply message sent"


        elif op_code == DISC_ECHO_REPLY:  # Handles the echo neibghour reply message/packet
            packet_fields = printDiscoverPacket(packet, L, length)  # gets the fields from the packet
            neighbor_vid = packet_fields[1]
            neighbor_port = event.port

            print "Neighbor discovery reply message received from: ", neighbor_vid

            self.viro.updateRoutingTable(neighbor_vid, neighbor_port)


        else:
            # printPacket(packet, L)
            dst = getDest(packet, L)  # gets the packet dst
            src = getSrc(packet, L)  # gets the packet src

            # forward the packet if I am not the destination
            if dst != self.vid:
                self.route_viro_packet(packet)
                return

            if op_code == RDV_QUERY:
                print "RDV_QUERY message received"
                if src == self.vid:
                    print "I am the rdv point - processing the packet"
                    self.viro.selfRVDQuery(packet)
                    return

                else:
                    rvdReplyPacket = self.viro.rvdQuery(packet)

                    if (rvdReplyPacket == ''):
                        return

                    mac = FAKE_MAC
                    msg = self.create_openflow_message(of.OFPP_IN_PORT, mac, rvdReplyPacket, event.port)

                    self.connection.send(msg)
                    print "RDV_REPLY message sent"


            elif op_code == RDV_PUBLISH:
                self.viro.rdvPublish(packet)


            elif op_code == RDV_REPLY:

                print "RDV_REPLY message received"
                self.viro.rdvReply(packet)

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


    def run_round(self, round):
        routingTable = self.viro.routingTable
        L = len(self.vid)

        # start from round 2 since connectivity in round 1 is already learnt using the physical neighbors
        for i in range(2, round + 1):

            # see if routing entry for this round is already available in the routing table.
            if i in routingTable:
                if len(routingTable[i]) > 0:

                    # publish the information if it is already there
                    for t in routingTable[i]:
                        if t[1] == int(self.vid, 2):
                            print "Sending rdv publish messages"
                            packet, dst = self.viro.publish(t, i)
                            self.route_viro_packet(packet)

                else:
                    print "Sending rdv query messages"

                    packet, dst = self.viro.query(i)
                    self.route_viro_packet(packet)
            else:

                print "Sending rdv query messages"
                packet, dst = self.viro.query(i)
                self.route_viro_packet(packet)


    def start_round(self):
        L = len(self.vid)

        print self.vid, 'Starting Round : ', self.round
        self.run_round(self.round)

        # Advance to next round but not beyond maximum (L)
        self.round += 1
        if self.round > L:
            self.round = L

        self.print_routing_table()


    def route_viro_packet(self, packet):
        # Type of packet: rvds Query or Publish
        # k - bucket level


        L = len(self.vid)
        dst = getDest(packet, L)

        # If it's me
        if (dst == self.vid):
            print 'I am the destination!'
            self.process_viro_packet(packet)
            return

        # get nextHop and port
        nextHop, port = self.viro.getNextHop(packet)
        if (nextHop != ''):
            hwrdst = FAKE_MAC
            msg = self.create_openflow_message(of.OFPP_IN_PORT, hwrdst, packet, int(port))
            self.connection.send(msg)
        else:
            print " Next hop is none "


    def print_routing_table(self):
        L = len(self.vid)
        print '\n\t----> Routing Table at :', self.vid, '|', self.dpid, ' <----'
        for bucket in range(1, L + 1):
            if bucket in self.viro.routingTable:
                for field in self.viro.routingTable[bucket]:
                    print 'Bucket::', bucket,\
                        'Nexthop:', bin2str(field[0], L),\
                        'Port:', field[2],\
                        'Gateway:', bin2str(field[1], L),\
                        'Prefix:', field[3]
            else:
                print 'Bucket', bucket, '  --- E M P T Y --- '
        print 'RDV STORE: ', self.viro.rdvStore
        print '\n --  --  --  --  -- --  --  --  --  -- --  --  --  --  -- \n'
