# OPERATIONS
VIRO_DATA_OP =            0x0000
RDV_PUBLISH =             0x1000
RDV_QUERY =               0x2000
RDV_REPLY =               0x3000
DISCOVERY_ECHO_REQUEST =  0x4000
DISCOVERY_ECHO_REPLY =    0x5000
GW_WITHDRAW =             0x6000
RDV_WITHDRAW =            0x7000
VIRO_DATA =               0x0802
VIRO_CONTROL =            0x0803

# OTHER PARTS OF THE HEADER
HTYPE = 0x1
PTYPE = 0x0800
HLEN = 0x06
PLEN = 0x04

# HARDWARE ADDRESS FOR THE VEIL MASTER
VEIL_MASTER_MAC = "00:00:00:00:00:00"

# An arbitrary/fake MAC address that seems to be used in various places
FAKE_MAC = '00:14:4f:e2:b3:70'

# OFFSET FOR THE OPER
OPER_OFFSET = 6
OPER_LEN = 2

# OFFSET FOR THE ECHO_SRC_VID
ECHO_SRC_OFFSET = 8

# The following _TIME parameter are all measured in seconds
ROUND_TIME = 10     # Time between "bottom up" rounds for routing table construction (RDV_PUBLISH / RDV_QUERY)
DISCOVER_TIME = 5   # Time between checking neighbor status
FAILURE_TIME = 7    # Time between checks for failures

# OPERATION NUMBER TO STRING MAPPING
OPERATION_NAMES = {
    0x1000: 'RDV_PUBLISH',
    0x2000: 'RDV_QUERY',
    0x3000: 'RDV_REPLY',
    0x4000: 'DISCOVERY_ECHO_REQUEST',
    0x5000: 'DISCOVERY_ECHO_REPLY',
    0x7000: 'RDV_WITHDRAW',
    0x6000: 'GW_WITHDRAW'
}

