# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
An L2 viro POX controller.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.packet import *
from pox.lib.addresses import *
from pox.lib.util import *
import time
import sys
from viro_module import viroModule
from viro_constant import *
from viro_veil import *
from pox.lib.recoco import Timer


log = core.getLogger()
myViro = ""
mydpid = 0
myvid = 0
round = 1


class ViroSwitch(object):

    def __init__(self, connection, transparent):

        self.connection = connection
        self.transparent = transparent

        # We want to hear PacketIn messages, so we listen
        connection.addListeners(self)


    def processViroPacket(self, packet, match=None, event=None):


        global myvid, mydpid, myViro
        L = len(myvid)
        length = getdpidLength(mydpid)

        opcode = getopcode(packet)

        if opcode == DISC_ECHO_REQ:  # Handles the echo neibghour discover message/packet
            # sends a disc_echo_reply packet

            packet_fields = printDiscoverPacket(packet, L, length)  # gets the fields from the packet
            nvid = packet_fields[1]  # direct neigbour VID

            print "Neighbour discover Request message received from: ", nvid
            r = createDISCOVER_ECHO_REPLY(myvid, mydpid)
            mac = '00:14:4f:e2:b3:70'

            msg = self.createOPENFLOW_Message(of.OFPP_IN_PORT, mac, r, event.port)

            self.connection.send(msg)
            print "Neighbour discover Reply message sent"


        elif opcode == DISC_ECHO_REPLY:  # Handles the echo neibghour reply message/packet
            # process the packet

            packet_fields = printDiscoverPacket(packet, L, length)  # gets the fields from the packet
            nvid = packet_fields[1]  # direct neigbour VID
            nport = event.port  # direct neigbour port

            print "Neighbour discover Reply message received from: ", nvid
            myViro.updateRoutingTable(nvid, nport)


        else:

            # printPacket(packet, L)
            dst = getDest(packet, L)  # gets the packet dst
            src = getSrc(packet, L)  # gets the packet src

            # forward the packet if I am not the destination
            if dst != myvid:
                self.routeViroPacket(packet)
                return

            if opcode == RDV_QUERY:

                print "RDV_QUERY message received"
                if src == myvid:
                    print "I am the rdv point - processing the packet"
                    myViro.selfRVDQuery(packet)
                    return

                else:
                    rvdReplyPacket = myViro.rvdQuery(packet)

                    if (rvdReplyPacket == ''):
                        return

                    mac = '00:14:4f:e2:b3:70'  # A fake MAC address.
                    msg = self.createOPENFLOW_Message(of.OFPP_IN_PORT, mac, rvdReplyPacket, event.port)

                    self.connection.send(msg)
                    print "RDV_REPLY message sent"


            elif opcode == RDV_PUBLISH:
                myViro.rdvPublish(packet)


            elif opcode == RDV_REPLY:

                print "RDV_REPLY message received"
                myViro.rdvReply(packet)

            elif opcode == VIRO_DATA_OP:
                # The part where it handles VIRO data packet
                print "Received a VIRO Data Packet"


    def createOPENFLOW_Message(self, openflow_port, mac, packet, event_port=None):
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
                    self.processViroPacket(mypacket, match, event)  # handling the VIRO REQUEST
                    return
        except:
            print "Error while processing packet"


    def runARound(self, round):
        global myViro
        routingTable = myViro.routingTable
        global mydpid, myvid
        mydpid = mydpid
        L = len(myvid)


        # start from round 2 since connectivity in round 1 is already learnt using the physical neighbors
        for i in range(2, round + 1):

            # see if routing entry for this round is already available in the routing table.
            if i in routingTable:
                if len(routingTable[i]) > 0:

                    # publish the information if it is already there
                    for t in routingTable[i]:
                        if t[1] == int(myvid, 2):
                            print "Sending rdv publish messages"
                            packet, dst = myViro.publish(t, i)
                            self.routeViroPacket(packet)

                else:
                    print "Sending rdv query messages"

                    packet, dst = myViro.query(i)
                    self.routeViroPacket(packet)
            else:

                print "Sending rdv query messages"
                packet, dst = myViro.query(i)
                self.routeViroPacket(packet)


    def startRound(self):
        global myvid, myViro, mydpid, round
        L = len(myvid)

        print myvid, 'Starting Round : ', round
        self.runARound(round)
        round = round + 1

        if round > L:
            round = L

        print '\n\t----> Routing Table at :', myvid, '|', mydpid, ' <----'
        for i in range(1, L + 1):
            if i in myViro.routingTable:
                for j in myViro.routingTable[i]:
                    print 'Bucket::', i, 'Nexthop:', bin2str(j[0], L), 'Port:', j[2], 'Gateway:', bin2str(j[1],
                                                                                                          L), 'Prefix:', \
                    j[3]
            else:
                print 'Bucket', i, '  --- E M P T Y --- '
        print 'RDV STORE: ', myViro.rdvStore
        print '\n --  --  --  --  -- --  --  --  --  -- --  --  --  --  -- \n'


    def routeViroPacket(self, packet):
        global myvid, myViro

        # Type of packet: rvds Query or Publish
        # k - bucket level        


        L = len(myvid)
        dst = getDest(packet, L)

        # If it's me
        if (dst == myvid):
            print 'I am the destination!'
            self.processViroPacket(packet)
            return

            # get nextHop and port
        nextHop, port = myViro.getNextHop(packet)
        if ( nextHop != ''):

            hwrdst = '00:14:4f:e2:b3:70'

            msg = self.createOPENFLOW_Message(of.OFPP_IN_PORT, hwrdst, packet, int(port))

            self.connection.send(msg)
        else:
            print " Next hop is none "


class viro_controller(object):
    """
    Waits for OpenFlow switches to connect.
    """

    def __init__(self, transparent):
        core.openflow.addListeners(self)
        self.transparent = transparent
        self.myviroSwitch = ''

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection,))
        self.myviroSwitch = ViroSwitch(event.connection, self.transparent)

        print "Starting Neighbor Discovery ...."
        global mydpid, myViro, myvid

        mydpid = dpidToStr(event.connection.dpid)   # gets the switch dpid identifier
        myvid = self.get_vid_from_pid(mydpid)
        myViro = viroModule(mydpid, myvid)

        # Call neighbour discovery function after every DISCOVER_TIME seconds
        Timer(DISCOVER_TIME, self.neighborDiscover, args=[mydpid, myvid, event], recurring=True)
        # Poulate routing table after every UPDATE_RT_TIME seconds
        Timer(UPDATE_RT_TIME, self.myviroSwitch.startRound, recurring=True)
        # Look for failures in the neigbours switches
        Timer(FAILURE_TIME, self.discoveryFailure, recurring=True)

    def get_vid_from_pid(self, pid):
        # To convert a pid string (assumed to be formatted like a MAC address: xx-xx-xx-xx-xx-xx)
        # starting at "00-00-00-00-00-01" to a vid string (of '1' and '0' characters)
        # starting at "000" we do the following:
        #   1. Remove "-" characters to make the string numeric
        #   2. Convert that string to an integer (assuming base 16)
        #   3. Subtract 1 so that "00-00-00-00-00-01" corresponds with "000"
        #   4. Convert the int back into a string using base 2
        #   5. Zero-pad the result the 3 bits to match the behavior of the original function
        return format(int(pid.replace('-', ''), 16) - 1, 'b').zfill(3)

    def neighborDiscover(self, mydip, myvid, event):

        try:
            dpid = mydip
            r = createDISCOVER_ECHO_REQ(myvid, dpid)
            mac = '00:14:4f:e2:b3:70'  # A fake MAC address.
            msg = self.myviroSwitch.createOPENFLOW_Message(of.OFPP_FLOOD, mac, r, None)
            event.connection.send(msg)
            print "Sending neighbour discover packets"

        except:
            print "Error .... not able to send discover packets"


    def discoveryFailure(self):
        # This is the function handling failure events
        # Random code, delete this when you are doing it.
        csci = 5221


def launch(transparent=False):
    """
    Starts an VIRO switch.
    """

    core.registerNew(viro_controller, str_to_bool(transparent))
