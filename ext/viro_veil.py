import socket, struct, sys, random
# from collections  import namedtuple

# Local imports 
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
    if operation in OPERATION_NAMES:
        return OPERATION_NAMES[operation]
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


# returns the rendezvousID for a node
def get_rendezvous_id(dist, vid):
    # returns the k character long string containing hash of the input value
    # FIXME: Appears to return all zeros for everything right now
    def hash_val(key, length):
        return length * '0'
    L = len(vid)
    rdv_id = vid[:L - dist + 1]
    return rdv_id + hash_val(rdv_id, dist - 1)


#  returns the op code type for a packet
def get_op_code(packet):
    [op_code] = struct.unpack("!H", packet[14:16])
    return op_code


# receives a packet from a tcp socket, waits till it receives NULL
def receive_packet(sock):
    data = sock.recv(128)
    '''packet = ''
    while data != '':
        packet = packet+data
        data = sock.recv(64)
        print 'data received: ', data'''
    return data


# check if the bucket is already present in the set or not:
def is_duplicate_bucket(bucket_list, bucket):
    is_duplicate = False
    for i in range(0, len(bucket_list)):
        all_fields_equal = True
        for j in bucket:
            if bucket_list[i][j] != bucket[j]:
                all_fields_equal = False
        if all_fields_equal:
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
    return fwd + res + pack_header(DISCOVERY_ECHO_REQUEST) + src_vid + pack_mac(dst_dpid)


def create_DISCOVER_ECHO_REPLY(vid, dpid):
    fwd = struct.pack('!I', int('0', 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    return fwd + res + pack_header(DISCOVERY_ECHO_REPLY) + src_vid + pack_mac(dpid)


def create_VIRO_DATA(src_vid, dst_vid, fwd_vid, ttl, payload):
    fwd = struct.pack('!I', int(dst_vid, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(src_vid, 2))
    dst_vid = struct.pack("!I", int(dst_vid, 2))
    p = struct.pack("!I", payload)
    return fwd + res + pack_header(VIRO_DATA_OP) + src_vid + dst_vid + p


def create_RDV_PUBLISH(bucket, vid, dst):
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Destination VID (32 bits)
    z = struct.pack("!I", bucket['next_hop']) # Destination Subtree-k
    return fwd + res + pack_header(RDV_PUBLISH) + src_vid + dst_vid + z


# bucket_dist is an int; other arguments are binary strings
def create_RDV_QUERY(bucket_distance, vid, dst):
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Destination VID (32 bits)
    z = struct.pack("!I", bucket_distance)   # Destination Subtree-k
    return fwd + res + pack_header(RDV_QUERY) + src_vid + dst_vid + z


# gw is an int; other arguments are binary strings
def create_RDV_REPLY(gw, bucket_distance, vid, dst):
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Destination VID (32 bits)
    bucket_distance = struct.pack("!I", bucket_distance)
    z = struct.pack("!I", gw) # Destination Subtree-k
    return fwd + res + pack_header(RDV_REPLY) + src_vid + dst_vid + bucket_distance + z


def create_RDV_WITHDRAW(failed_node, vid, dst):
    # print 'create_RDV_WITHDRAW', failed_node, vid, dst
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Destination VID (32 bits)
    z = struct.pack("!I", failed_node) # Destination Subtree-k
    return fwd + res + pack_header(RDV_WITHDRAW) + src_vid + dst_vid + z


def create_GW_WITHDRAW(failed_gw, vid, dst):
    # print 'create_GW Withdraw', vid, dst, failed_gw
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Destination VID (32 bits)
    z = struct.pack("!I", int(failed_gw, 2)) # Destination Subtree-k
    return fwd + res + pack_header(GW_WITHDRAW) + src_vid + dst_vid + z


# flips the kth bit (from the right) in the dst and returns it.
def flip_bit(dst, distance):
    L = len(dst)
    prefix = dst[:L - distance]
    if dst[L - distance] == '0':
        prefix = prefix + '1'
    else:
        prefix = prefix + '0'
    prefix = prefix + dst[L - distance + 1:]
    return prefix


# prints the packet content
def print_packet(packet, L):
    [op_code] = struct.unpack("!H", packet[14:16])  # 6:8
    [src_vid] = struct.unpack("!I", packet[16:20])
    [dst_vid] = struct.unpack("!I", packet[20:24])
    [payload] = struct.unpack("!I", packet[24:28])

    if op_code not in OPERATION_NAMES:
        print 'Unknown packet op_code: ', hex(op_code)
        print 'Content in hexadecimal: ', packet.encode("hex")
        return
    print 'Type: ', OPERATION_NAMES[op_code],\
        'Source: ', bin2str(src_vid, L),\
        'Destination: ', bin2str(dst_vid, L),\
        'Payload: ', bin2str(payload, L)


# print DiscoveryPacket
def print_discover_packet(packet, L, length):
    [op_code] = struct.unpack("!H", packet[14:16])  # 3:5

    [svid] = struct.unpack("!I", packet[16:20])
    #[dpid1] = struct.unpack("!I", packet[12:18])

    #[port] = struct.unpack("!I",packet[18:22]) #15:19
    #[payload] = struct.unpack("!I", packet[16:20])


    if op_code not in OPERATION_NAMES:
        print 'Unknown packet op_code: ', hex(op_code)
        print 'Content in hexadecimal: ', packet.encode("hex")
        # Need to return none if no match
        #return 
    #print 'Type: ',OPERATION_NAMES[op_code], 'VID: ', bin2str(svid,L), 'dpid: ', bin2str(dpid,length), 'port : ' , [port][0]
    #print 'Type: ',OPERATION_NAMES[op_code], 'VID: ', bin2str(svid,L), 'port : ' , [port][0]
    return (op_code, bin2str(svid, L))


# converts the binary representation of an integer to binary string.
def bin2str(id, L):
    bin_str = bin(id)
    bin_str = bin_str.replace('0b', '')
    bin_str = (L - len(bin_str)) * '0' + bin_str
    return bin_str


# logical distance 
def delta(vid1, vid2):
    L = len(vid1)
    distance = L
    for i in range(0, L):
        if vid1[i] == vid2[i]:
            distance = distance - 1
        else:
            return distance
    return distance
