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

from viro_module import viroModule
from viro_constant import *
from viro_veil import *
from viro_switch import ViroSwitch

log = core.getLogger()
myViro = ""
mydpid = 0
myvid = 0

class ViroController(object):
    """
    Waits for OpenFlow switches to connect.
    """

    def __init__(self, transparent):
        core.openflow.addListeners(self)
        self.transparent = transparent
        self.myviroSwitch = ''

    def _handle_ConnectionUp(self, event):
        global mydpid, myViro, myvid
        log.debug("Connection %s" % (event.connection))

        mydpid = dpidToStr(event.connection.dpid)   # gets the switch dpid identifier
        myvid = self.get_vid_from_pid(mydpid)
        myViro = viroModule(mydpid, myvid)

        self.myviroSwitch = ViroSwitch(event.connection, self.transparent, myViro)

        print "Starting Neighbor Discovery ...."
        # Call neighbor discovery function after every DISCOVER_TIME seconds
        Timer(DISCOVER_TIME, self.discover_neighbors, args=[mydpid, myvid, event], recurring=True)
        # Populate routing table after every UPDATE_RT_TIME seconds
        Timer(UPDATE_RT_TIME, self.myviroSwitch.start_round, recurring=True)
        # Look for failures in the neigbours switches
        Timer(FAILURE_TIME, self.discover_failures, recurring=True)

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

    def discover_neighbors(self, mydip, myvid, event):
        try:
            dpid = mydip
            r = createDISCOVER_ECHO_REQ(myvid, dpid)
            mac = FAKE_MAC
            msg = self.myviroSwitch.create_openflow_message(of.OFPP_FLOOD, mac, r, None)
            event.connection.send(msg)
            print "Sending neighbor discovery packets"

        except:
            print "Error .... not able to send discovery packets"


    def discover_failures(self):
        # This is the function handling failure events
        # Random code, delete this when you are doing it.
        csci = 5221


def launch(transparent=False):
    """
    Starts an VIRO switch.
    """

    core.registerNew(ViroController, str_to_bool(transparent))
