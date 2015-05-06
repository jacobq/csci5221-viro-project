# Manually set L
L = 4

# OpenFlow Ethernet Frame type codes (dl_type)
VIRO_DATA =    0x0802   # See ../pox/lib/packet/ethernet.py: VIRO_TYPE = 0x0802
VIRO_CONTROL = 0x0803

OP_NAMES = {
    0x0000: 'VIRO_DATA_OP',
    0x1000: 'RDV_PUBLISH',
    0x2000: 'RDV_QUERY',
    0x3000: 'RDV_REPLY',
    0x4000: 'DISCOVERY_ECHO_REQUEST',
    0x5000: 'DISCOVERY_ECHO_REPLY',
    0x6000: 'GW_WITHDRAW',
    0x7000: 'RDV_WITHDRAW'
}

# Create inverse: op_name -> op_code mapping
OP_CODES = {}
for op_code, name in OP_NAMES.items():
    OP_CODES[name] = op_code

# OTHER PARTS OF THE HEADER
HTYPE = 0x1
PTYPE = 0x0800
HLEN = 0x06
PLEN = 0x04
MAX_TTL = 16  # 16 hops ought to be more than enough since that's every node in the example topology!

# Per the CSCI 5221 Project 2 assignment document:
# "We limit the maximal number of < Gateway; Nexthop > pairs in each level to 3."
MAX_GW_PER_LEVEL = 3
MAX_GW_PER_RDV_REPLY = MAX_GW_PER_LEVEL


# The range of hardware/MAC addresses
# 00:14:4F:F8:00:00 - 00:14:4F:FF:FF:FF
# is registered to Oracle Corporation and appears to have been used
# in some of their old software (Logical Domain Manager?)
# rather than in the manufacturing of NICs.
# See http://docs.oracle.com/cd/E19604-01/821-0406/rangeofmacaddressesassignedtoldoms/index.html
# However, I believe FAKE_SRC_MAC is basically just an arbitrary address (not specially chosen)
FAKE_SRC_MAC = '00:14:4f:e2:b3:70'
VEIL_MASTER_MAC = '00:00:00:00:00:00'


# OFFSET FOR THE OPER
# Account for extra 8 bytes stuffed in front (fwd + res + dl_type) whose meaning is beyond the scope of this assignment
OPER_OFFSET = 8 + 6
OPER_LEN = 2


# OFFSET FOR THE ECHO_SRC_VID
ECHO_SRC_OFFSET = 8


# The following _TIME parameter are all measured in seconds
ROUND_TIME = 10              # Time between "bottom up" rounds for routing table construction (RDV_PUBLISH / RDV_QUERY)
DISCOVER_TIME = 5            # Time between checking neighbor status
FAILURE_TIME = 7             # Time between checks for failures
ROUTING_DEMO_PACKET_TIME = 2 # Time between sending sample VIRO_DATA packets to demonstrate routing functionality
NEIGHBOR_EXPIRATION_TIME = 3*DISCOVER_TIME # Neighbor entries older than this will be removed