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

import traceback

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import *
from pox.lib.recoco import Timer

from viro_constant import L
from viro_module import ViroModule
from viro_switch import ViroSwitch
from viro_veil import *

log = core.getLogger()

class ViroController(object):
    """
    Waits for OpenFlow switches to connect.
    """

    def __init__(self, transparent):
        core.openflow.addListeners(self)
        self.transparent = transparent

    # Runs when the switch/controller is started (not when a link comes up!)
    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection))

        self.dpid = dpidToStr(event.connection.dpid)   # gets the switch dpid identifier
        self.vid = self.get_vid_from_dpid(self.dpid)
        self.viro = ViroModule(self.dpid, self.vid)
        self.viro_switch = ViroSwitch(event.connection, self.transparent, self.viro)

        log.debug("Starting periodic tasks (recurring timers)")
        Timer(DISCOVER_TIME, self.discover_neighbors, args=[event], recurring=True)
        Timer(FAILURE_TIME, self.discover_failures, recurring=True)
        Timer(ROUND_TIME, self.viro_switch.start_round, recurring=True)
        Timer(ROUTING_DEMO_PACKET_TIME, self.viro_switch.send_sample_viro_data, recurring=True)

    def get_vid_from_dpid(self, dpid):
        # To convert a dpid string (assumed to be formatted like a MAC address: xx-xx-xx-xx-xx-xx)
        # starting at "00-00-00-00-00-01" to a vid string (of '1' and '0' characters)
        # starting at "000" we do the following:
        #   1. Remove "-" characters to make the string numeric
        #   2. Convert that string to an integer (assuming base 16)
        #   3. Subtract 1 so that "00-00-00-00-00-01" corresponds with "000"
        #   4. Convert the int back into a string using base 2
        #   5. Zero-pad the result to L bits
        return format(int(dpid.replace('-', ''), 16) - 1, 'b').zfill(L)

    def discover_neighbors(self, event):
        try:
            r = create_DISCOVER_ECHO_REQUEST(self.vid, self.dpid)
            msg = self.viro_switch.create_openflow_message(of.OFPP_FLOOD, FAKE_SRC_MAC, r, None)
            event.connection.send(msg)
            print "Sending neighbor discovery packets"

        except:
            print "ERROR: caught exception during neighbor discovery. Not able to send discovery packets?"
            print traceback.format_exc()

    def discover_failures(self):
        try:
            self.viro.remove_expired_neighbors()
        except:
            print "ERROR: Caught exception during discover_failures"
            print traceback.format_exc()

def launch(transparent=False):
    """
    Starts a VIRO controller/switch
    """

    core.registerNew(ViroController, str_to_bool(transparent))
