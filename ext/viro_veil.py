import socket, struct, sys, random, traceback

from viro_constant import *

def get_dpid_length(dpid):
    dpid_bytes = dpid.split("-")
    return len(dpid_bytes) * 8

# convert a string containing mac address into a byte array
def get_mac_array(mac):
    mac_array = [0] * 6
    mac_bytes = mac.split("-")
    if len(mac_bytes) != 6:
        print 'Error: MalFormed mac, expected 6 bytes, found : ', len(mac_bytes), 'bytes in the input array: ', mac
    for i in range(0, 6):
        if i < len(mac_bytes):
            mac_array[i] = int(mac_bytes[i], 16)
    return mac_array

# convert a byte array into the string format            
def get_mac_hex_string(mac_bytes):
    mac_string = ''
    for i in range(0, 6):
        s = hex(mac_bytes[i]).replace('0x', '')
        if len(s) < 2:
            mac_string += '0'
        mac_string += s
        if i < 5:
            mac_string += ':'
    return mac_string


# get the prefix of kth bucket (k = dist) for node vid
def get_prefix(vid, dist):
    L = len(vid)
    prefix = vid[:L - dist]
    # flip the (dist-1)th bit from the right
    if vid[L - dist] == '0':
        prefix += '1'
    else:
        prefix += '0'
    prefix += (dist - 1) * '*'
    return prefix

# Extract the operation from the packet
def get_operation(packet):
    operation = (struct.unpack('!H', packet[OPER_OFFSET: OPER_OFFSET + OPER_LEN]))[0]
    return operation

# convert operation number into a string
def get_operation_name(operation):
    if operation in OP_NAMES:
        return OP_NAMES[operation]
    else:
        return 'UNKNOWN OPERATION'

# returns the destination in the string format
def get_dest(packet, L):
    t = struct.unpack("!I", packet[20:24])
    dest = bin2str(t[0], L)
    return dest

# returns the source in the string format
def get_src(packet, L):
    t = struct.unpack("!I", packet[16:20])
    src = bin2str(t[0], L)
    return src

# returns the ID of the rendezvous point for distance = dist from node = vid
# Right now, this is the first (L - dist + 1) bits of the vid followed by (dist-1) zeros
def get_rdv_id(dist, vid):
    def hash_val(key, length):
        return length * '0'
    L = len(vid)
    rdv_id = vid[:L - dist + 1]
    return rdv_id + hash_val(rdv_id, dist - 1)

#  returns the op code type for a packet
def get_op_code(packet):
    [op_code] = struct.unpack("!H", packet[14:16])
    return op_code

# check if the bucket is already present in the set or not:
def is_duplicate_bucket(bucket_list, new_bucket):
    is_duplicate = False
    for bucket in bucket_list:
        if bucket['prefix'] == new_bucket['prefix'] and \
           bucket['gateway'] == new_bucket['gateway'] and \
           bucket['next_hop'] == new_bucket['next_hop']:
            is_duplicate = True
            return is_duplicate
    return is_duplicate

def pack_header(operation):
    return struct.pack("!HHBBH", HTYPE, PTYPE, HLEN, PLEN, operation)

def pack_mac(data):
    return pack_bytes(get_mac_array(data))

def pack_bytes(data):
    result = ''
    for byte in data:
        result += struct.pack("!B", byte)
    return result

def create_DISCOVER_ECHO_REQUEST(vid, dst_dpid):
    fwd = struct.pack('!I', 0)
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2))    # Sender VID (32 bits)
    return fwd + res + pack_header(OP_CODES['DISCOVERY_ECHO_REQUEST']) + src_vid + pack_mac(dst_dpid)

def create_DISCOVER_ECHO_REPLY(vid, dpid):
    fwd = struct.pack('!I', int('0', 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    return fwd + res + pack_header(OP_CODES['DISCOVERY_ECHO_REPLY']) + src_vid + pack_mac(dpid)

# This function generates/encodes/packs the "Data Packet" described in the
# first subtask of task 2. Conveniently, the fwd_vid and ttl parameters
# are already listed in the arguments.
# Note that "fwd" and "res" are unrelated & outside the scope of this project
# (Guobao said to leave them in place as they're for POX / Open vSwitch, so I will)
# ttl is an integer, and all other arguments are strings of '0's and '1's
def create_VIRO_DATA(src_vid, dst_vid, fwd_vid, ttl, payload):
    fwd = struct.pack('!I', int(dst_vid, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid_packed = struct.pack("!I", int(src_vid, 2))
    dst_vid_packed = struct.pack("!I", int(dst_vid, 2))
    fwd_vid_packed = struct.pack("!I", int(fwd_vid, 2))    # FWD-VID: forwarding directive
    ttl_and_padding = struct.pack("!BBH", ttl, 0, 0)
    payload_packed = struct.pack("!I", int(payload, 2))    # Assume for now that payload is just an integer
    return fwd + res + pack_header(OP_CODES['VIRO_DATA_OP']) +\
           src_vid_packed + dst_vid_packed + fwd_vid_packed +\
           ttl_and_padding + payload_packed

def create_RDV_PUBLISH(bucket, vid, dst):
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Destination VID (32 bits)
    next_hop = struct.pack("!I", bucket['next_hop']) # Destination Subtree-k
    return fwd + res + pack_header(OP_CODES['RDV_PUBLISH']) + src_vid + dst_vid + next_hop

# bucket_dist is an int; other arguments are binary strings
def create_RDV_QUERY(bucket_distance, vid, dst):
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Destination VID (32 bits)
    return fwd + res + pack_header(OP_CODES['RDV_QUERY']) + src_vid + dst_vid + struct.pack("!I", bucket_distance)

# gw_list is a list of integers; other arguments are binary strings
def create_RDV_REPLY(gw_list, bucket_distance, vid, dst):
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Destination VID (32 bits)
    bucket_distance = struct.pack("!I", bucket_distance)
    gateways = ""
    for gw in gw_list:
        gateways += struct.pack("!I", gw)
    return fwd + res + pack_header(OP_CODES['RDV_REPLY']) + src_vid + dst_vid + bucket_distance + gateways

def create_RDV_WITHDRAW(failed_node, vid, dst):
    # print 'create_RDV_WITHDRAW', failed_node, vid, dst
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Destination VID (32 bits)
    return fwd + res + pack_header(OP_CODES['RDV_WITHDRAW']) + src_vid + dst_vid + struct.pack("!I", failed_node)

def create_GW_WITHDRAW(failed_gw, vid, dst):
    # print 'create_GW Withdraw', vid, dst, failed_gw
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Destination VID (32 bits)
    z = struct.pack("!I", int(failed_gw, 2)) # Destination Subtree-k
    return fwd + res + pack_header(OP_CODES['GW_WITHDRAW']) + src_vid + dst_vid + z

# flips the kth bit (from the right) in the dst and returns it.
def flip_bit(dst, distance):
    L = len(dst)
    prefix = dst[:L - distance]
    if dst[L - distance] == '0':
        prefix += '1'
    else:
        prefix += '0'
    prefix = prefix + dst[L - distance + 1:]
    return prefix

def decode_discovery_packet(packet, L, dpid_length):
    [op_code] = struct.unpack("!H", packet[14:16])
    [svid] = struct.unpack("!I", packet[16:20])
    dpid_bytes = (dpid_length/8)
    if len(packet) >= (20+dpid_bytes):
        dst_dpid_str = ""
        for dst_dpid_byte in struct.unpack("!" + "B"*dpid_bytes, packet[20:(20+dpid_bytes)]):
            dst_dpid_str += hex(dst_dpid_byte).replace("0x", "").zfill(2)
        dst_dpid = int(dst_dpid_str, 16)
    else:
        print "ERROR: decode_discovery_packet did not get dst_dpid"
        dst_dpid = 0

    return {
        'op_code': op_code,
        'sender_vid': bin2str(svid, L),
        'dst_dpid': dst_dpid
    }

# Takes packed string representation of VIRO_DATA_OP packet and L
# Returns dictionary with the fields after the op code
# (i.e. the one specific to VIRO_DATA_OP packets)
# The VIDs are returned as strings of '0's and '1's
# The TTL is returned as an integer
# The payload is also returned as a string of '0's and '1's
def decode_viro_data_packet_contents(packet, L):
    try:
        # Ignore encapsulating header bytes 0-15
        src_vid = struct.unpack("!I", packet[16:20])
        dst_vid = struct.unpack("!I", packet[20:24])
        fwd_vid = struct.unpack("!I", packet[24:28])
        ttl = struct.unpack("!B", packet[28:29])
        # Ignore padding bytes 29-31
        payload = struct.unpack("!I", packet[32:36])
        return {
            'src_vid': bin2str(src_vid, L),
            'dst_vid': bin2str(dst_vid, L),
            'fwd_vid': bin2str(fwd_vid, L),
            'ttl': ttl,
            'payload': bin2str(payload, 8)
        }
    except:
        # Should never happen in our isolated system since no one else is
        # sending us these packets and we guarantee proper format/encoding.
        # Nevertheless we try to detect this error and log as a best practice.
        print "ERROR: encountered malformed VIRO_DATA_OP packet"
        print traceback.format_exc()

# converts the binary representation of an integer to binary string.
def bin2str(id, L):
    bin_str = bin(id).replace('0b', '')
    bin_str = (L - len(bin_str)) * '0' + bin_str
    return bin_str

# logical distance 
def delta(vid1, vid2):
    L = len(vid1)
    distance = L
    for i in range(0, L):
        if vid1[i] == vid2[i]:
            distance -= 1
        else:
            return distance
    # print "Logical distance between ", vid1, "and", vid2, "is", distance
    return distance

######################################
# Debug functions
def print_packet(packet, L, verbose=False):
    def hex_value(i, num_bytes=1):
        return '0x' + hex(i).replace('0x', '').zfill(2*num_bytes)

    # print "print_packet found", len(packet), "bytes:"
    if verbose:
        print get_pretty_hex(packet, 2, 4)

    if verbose:
        if (len(packet) >= 4):
            [fwd] = struct.unpack("!I", packet[0:4])
            print 'fwd:', hex_value(fwd, 4)

        if (len(packet) >= 6):
            [res] = struct.unpack("!H", packet[4:6])
            print 'res:', hex_value(fwd, 2)

        if (len(packet) >= 8):
            [of_type] = struct.unpack("!H", packet[6:8])
            if of_type != VIRO_CONTROL:
                print "WARNING: This packet does not have dl_type == VIRO_CONTROL"
            print 'of_type:', hex_value(of_type, 2)

        if (len(packet) >= 10):
            [htype] = struct.unpack("!H", packet[8:10])
            print 'HTYPE:', hex_value(htype, 2)

        if (len(packet) >= 12):
            [ptype] = struct.unpack("!H", packet[10:12])
            print 'PTYPE:', hex_value(ptype, 2)

        if (len(packet) >= 13):
            [hlen] = struct.unpack("!B", packet[12])
            print 'HLEN:', hlen

        if (len(packet) >= 14):
            [plen] = struct.unpack("!B", packet[13])
            print 'PLEN:', plen

    if (len(packet) >= 16):
        [op_code] = struct.unpack("!H", packet[14:16])
        print 'Type:', get_operation_name(op_code)

    if (len(packet) >= 20):
        [src_vid] = struct.unpack("!I", packet[16:20])
        print  'Source:', bin2str(src_vid, L)

    if (len(packet) >= 24):
        [dst_vid] = struct.unpack("!I", packet[20:24])
        print 'Destination:', bin2str(dst_vid, L)

    if (len(packet) > 24):
        if op_code == OP_CODES['VIRO_DATA_OP'] and len(packet) >= 32:
            [fwd_vid] = struct.unpack("!I", packet[24:28])
            print 'Forwarding directive:', bin2str(fwd_vid, L)
            [ttl] = struct.unpack("!B", packet[28])
            print 'TTL:', ttl
            print 'Payload:', "0x" + packet[32:].encode("hex")
        else:
            print 'Payload:', "0x" + packet[24:].encode("hex")

    print "" # add new line to separate this output in the log

def get_pretty_hex(packed_data, nybbles_per_word, words_per_line):
    # Breaks sequences/arrays into nice groups
    # http://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks-in-python
    def chunks(l, n):
        n = max(1, n)
        return [l[i:i + n] for i in range(0, len(l), n)]

    return '\n'.join(chunks(
            ' '.join(chunks(packed_data.encode("hex"), nybbles_per_word)),
            (nybbles_per_word+1)*words_per_line))
