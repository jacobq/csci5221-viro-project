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
    #t 'mac_bytes: ', mac_bytes
    for i in range(0, 6):
        if i < len(mac_bytes):
            mac_array[i] = int(mac_bytes[i], 16)
    return mac_array


# convert a byte array into the string format            
def get_mac_hex_string(bytes):
    macstring = ''
    #print "Converting Bytes: ", bytes
    for i in range(0, 6):
        #print 'Bytes[i] = ', bytes[i]
        #print 'hex = ', hex(bytes[i])
        s = hex(bytes[i]).replace('0x', '')
        if len(s) < 2:
            s = '0' + s
        macstring = macstring + s
        if i < 5:
            macstring = macstring + ':'
    return macstring


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


# extract IP/VID mapping to store:
def extract_ip_to_store(store_request_packet):
    #print 'start offset: ',ECHO_SRC_OFFSET+2*HLEN
    #print 'end offset: ', ECHO_SRC_OFFSET+2*HLEN +PLEN
    #print 'String buffer: ', store_request_packet[ECHO_SRC_OFFSET+2*HLEN:ECHO_SRC_OFFSET+2*HLEN+PLEN]
    ip_num = struct.unpack("!4s", store_request_packet[ECHO_SRC_OFFSET + 2 * HLEN:ECHO_SRC_OFFSET + 2 * HLEN + PLEN])
    return socket.inet_ntoa(ip_num[0])


def extract_vid_to_store(store_request_packet):
    vid = struct.unpack("!BBBBBB",
                        store_request_packet[ECHO_SRC_OFFSET + 2 * HLEN + PLEN:ECHO_SRC_OFFSET + 3 * HLEN + PLEN])
    return get_mac_hex_string(vid)


# extract source  vid from echopacket
def extract_echo_src(echo_packet):
    src_vid = struct.unpack("!BBBBBB", echo_packet[ECHO_SRC_OFFSET:ECHO_SRC_OFFSET + HLEN])
    return get_mac_hex_string(src_vid)


# extract source vid from echopacket
def extract_echo_dst(echo_packet):
    dstvid = struct.unpack("!BBBBBB", echo_packet[ECHO_SRC_OFFSET + HLEN:ECHO_SRC_OFFSET + 2 * HLEN])
    return get_mac_hex_string(dstvid)


# extract source vid from echopacket
def extract_arp_src_mac(arppacket):
    srcmac = struct.unpack("!BBBBBB", arppacket[ECHO_SRC_OFFSET:ECHO_SRC_OFFSET + HLEN])
    return get_mac_hex_string(srcmac)


# extract source vid from echopacket
def extract_arp_dst_mac(arp_packet):
    mac = struct.unpack("!BBBBBB", arp_packet[ECHO_SRC_OFFSET + HLEN + PLEN:ECHO_SRC_OFFSET + 2 * HLEN + PLEN])
    return get_mac_hex_string(mac)


# extract IP addresses
def extract_arp_dst_ip(arp_packet):
    ip = struct.unpack("!4s", arp_packet[ECHO_SRC_OFFSET + 2 * HLEN + PLEN:ECHO_SRC_OFFSET + 2 * HLEN + 2 * PLEN])
    ip_address = socket.inet_ntoa(ip[0])
    return ip_address


def extract_arp_src_ip(arp_packet):
    ip = struct.unpack("!4s", arp_packet[ECHO_SRC_OFFSET + HLEN:ECHO_SRC_OFFSET + HLEN + PLEN])
    ip_address = socket.inet_ntoa(ip[0])
    return ip_address


# extract an IP address at a give offset
def extract_ip(packet, offset):
    ip = struct.unpack("!4s", packet[offset:offset + PLEN])
    ip_address = socket.inet_ntoa(ip[0])
    return ip_address


# extract a MAC address at a give offset
def extract_mac(packet, offset):
    mac = struct.unpack("!BBBBBB", packet[offset:offset + HLEN])
    return get_mac_hex_string(mac)


# receives a packet from a tcp socket, waits till it receives NULL
def receive_packet(sock):
    #print 'Receiving packet at socket: ',sock
    data = sock.recv(128)
    #print 'data received: ', data.encode("hex")
    '''packet = ''
    while data != '':
        packet = packet+data
        data = sock.recv(64)
        print 'data received: ', data'''
    return data


# Method for switch registration
def register_switch(veil_master_ip, veil_master_port, server_port):
    # Packet structure
    # HTYPE PTYPE HLEN PLEN OPER SRCVID(48bit) DSTVID(48bit) TCPPORT(16bit)
    print 'Register switch at port: ', server_port,\
          ' with VEIL_MASTER_MAC IP: ', veil_master_ip,\
          ' VEIL_MASTER_MAC PORT: ', veil_master_port
    registration_packet = pack_header(SWITCH_REGISTER_REQUEST) + pack_mac("ff:ff:ff:ff:ff:ff") +\
                          pack_mac(VEIL_MASTER_MAC) + struct.pack("!H", server_port)
    print 'Registration packet to be sent: ', registration_packet.encode("hex")
    sock_master = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_master.connect((veil_master_ip, veil_master_port))
    sock_master.send(registration_packet)
    registration_reply = receive_packet(sock_master)
    print 'Registration packet reply to be received: ', registration_reply.encode("hex")
    sock_master.close()
    return extract_mac(registration_reply, ECHO_SRC_OFFSET + HLEN)


# Gets a new ID for the switch. Basically generates a 32-bit random integer and checks if its in use or not
def get_a_new_switch_id(current_ids):
    MAXID = 2 ** 32 - 1
    if len(current_ids) == MAXID:
        print 'ERROR: NO more IDS left!'
        return 0
    #random.seed(1)
    id = random.randint(1, MAXID)
    while id in current_ids:
        id = random.randint(1, MAXID)
    return id


# converts an ID (32-bit number) into a VID format
def switch_id_to_vid(id):
    vid = '00:00'
    id_str = hex(id).replace('0x', '')
    id_str = id_str.lower()
    id_str = id_str.replace('l', '')

    while len(id_str) < 8:
        id_str = '0' + id_str
    vid = id_str[0:2] + ':' + id_str[2:4] + ':' + id_str[4:6] + ':' + id_str[6:8] + ':' + vid
    return vid


# This function determines the ID for the access switch.
def get_access_switch_id(ip, ids):
    MAXINT = 2 ** 32 - 1
    RADIUS = 2 ** 31
    if len(ids) == 0:
        return 0
    hash_val = hash(ip) % (MAXINT + 1)
    min_diff = MAXINT
    access_switch_id = 0
    for id in ids:
        diff = abs(hash_val - id) % (RADIUS)
        if diff < min_diff:
            access_switch_id = id
            min_diff = diff
    return access_switch_id


# Generates a unique host-vid
def get_a_vid(ip, mac, my_switch_vid, my_host_ids):
    MAX_HOSTID = 2 ** 16 - 1
    host_id = ''
    for i in range(1, MAX_HOSTID + 1):
        if i not in my_host_ids:
            break
    if i == MAX_HOSTID:
        print 'Warning: All the VIDs are currently in use!'
        host_id = "ff:ff"
    else:
        my_host_ids.append(i)
        id = hex(i).replace("0x", '')
        while len(id) < 4:
            id = '0' + id
        host_id = id[0:2] + ':' + id[2:4]
    bytes = my_switch_vid.split(":")
    vid = bytes[0] + ":" + bytes[1] + ":" + bytes[2] + ":" + bytes[3] + ":" + host_id
    return vid


# get the prefix of kth bucket (k = dist) for node vid
def get_prefix(vid, dist):
    L = len(vid)
    prefix = vid[:L - dist]
    # flip the (dist-1)th bit from the right
    if vid[L - dist] == '0':
        prefix = prefix + '1'
    else:
        prefix = prefix + '0'
    prefix = prefix + (dist - 1) * '*'
    return prefix


# check if the bucket is already present in the set or not:
def is_duplicate_bucket(bucket_list, bucket):
    is_duplicate = False
    for i in range(0, len(bucket_list)):
        if bucket_list[i][0] == bucket[0] and bucket_list[i][1] == bucket[1] and bucket_list[i][2] == bucket[2]:
            is_duplicate = True
            return is_duplicate
    return is_duplicate


# returns the rendezvousID for a node
def get_rendezvous_id(dist, vid):
    L = len(vid)

    rdv_id = vid[:L - dist + 1]
    rdv_id = rdv_id + hash_val(rdv_id, dist - 1)
    return rdv_id


# returns the k character long string containing hash of the input value
def hash_val(key, length):
    return length * '0'


def pack_header(operation):
    return struct.pack("!HHBBH", HTYPE, PTYPE, HLEN, PLEN, operation)

def pack_mac(data):
    return pack_bytes(get_mac_array(data))

def pack_bytes(data):
    result = ''
    for byte in data:
        result += struct.pack("!B", byte)
    return result


# creates an arp packet, OPER is the operation, mac_src is the source mac address as string, ip_src is the source ip as string
def create_arp_packet(op, mac_src, ip_src, mac_dst, ip_dst):
    ip_src_num = socket.inet_aton(ip_src)
    ip_dst_num = socket.inet_aton(ip_dst)
    arp_packet = pack_header(op) +\
                 pack_mac(mac_src) + struct.pack("!4s", ip_src_num) +\
                 pack_mac(mac_dst) + struct.pack("!4s", ip_dst_num)
    return arp_packet


def create_switch_registration_reply_packet(switch_vid):
    registration_reply = pack_header(SWITCH_REGISTER_REPLY) + pack_mac(VEIL_MASTER_MAC) + pack_mac(switch_vid)
    return registration_reply


# FIXME: What is the difference between create_switch_registration_reply_packet and create_switch_registration_reply_packet1?
def create_switch_registration_reply_packet1(src_vid, dst_vid):
    reply = pack_header(SWITCH_REGISTER_REPLY) + pack_mac(src_vid) + pack_mac(dst_vid)
    return reply


# create echo_request packet:
def create_echo_request_packet(src_vid, dst_vid):
    #Packet Structure: HTYPE PTYPE HLEN PLEN OPER SRC_VID(48) DST_VID(48)
    echo_request = pack_header(ECHO_REQUEST) + pack_mac(src_vid) + pack_mac(dst_vid)
    return echo_request


# create echo_request packet:
def create_echo_reply_packet(src_vid, dst_vid):
    echo_reply = pack_header(ECHO_REPLY) + pack_mac(src_vid) + pack_mac(dst_vid)
    return echo_reply


def create_store_packet(ip_to_store, vid_to_store, src_vid, dst_vid):
    # Packet Structure: HTYPE PTYPE HLEN PLEN OPER SRC_VID(48) DST_VID(48) IP_TO_STORE(32) VID_TO_STORE(48)
    # print 'Source VID: ', src_vid, 'Destination VID: ', dst_vid, ' IP to store: ', ip_to_store, 'vid to store: ', vid_to_store
    ip_num = socket.inet_aton(ip_to_store)
    store_packet = pack_header(STORE_REQUEST) + pack_mac(src_vid) + pack_mac(dst_vid) + struct.pack("!4s", ip_num) + pack_mac(vid_to_store)
    return store_packet


def create_DISCOVER_ECHO_REQ(vid, dst_dpid):
    fwd = struct.pack('!I', 0)
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2))    # Sender VID (32 bits)
    return fwd + res + pack_header(DISC_ECHO_REQ) + src_vid + pack_mac(dst_dpid)


def create_DISCOVER_ECHO_REPLY(vid, dpid):
    fwd = struct.pack('!I', int('0', 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    return fwd + res + pack_header(DISC_ECHO_REPLY) + src_vid + pack_mac(dpid)


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
    dst_vid = struct.pack("!I", int(dst, 2)) # Desitnation VID (32 bits)
    z = struct.pack("!I", bucket[0]) # Destination Subtree-k
    return fwd + res + pack_header(RDV_PUBLISH) + src_vid + dst_vid + z


# GW IS AN INT HERE! AND REST ARE BINARY STRINGS
def create_RDV_REPLY(gw, bucket_distance, vid, dst):
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Desitnation VID (32 bits)
    bucket_distance = struct.pack("!I", bucket_distance)
    z = struct.pack("!I", gw) # Destination Subtree-k
    return fwd + res + pack_header(RDV_REPLY) + src_vid + dst_vid + bucket_distance + z


# create a RDV_QUERY Pakcet
# bucket_dist IS AN INT HERE! AND REST ARE BINARY STRINGS
def create_RDV_QUERY(bucket_distance, vid, dst):
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Desitnation VID (32 bits)
    z = struct.pack("!I", bucket_distance)   # Destination Subtree-k
    return fwd + res + pack_header(RDV_QUERY) + src_vid + dst_vid + z


def create_RDV_WITHDRAW(failed_node, vid, dst):
    #print 'create_RDV_WITHDRAW', failed_node, vid, dst
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Desitnation VID (32 bits)
    z = struct.pack("!I", failed_node) # Destination Subtree-k
    return fwd + res + pack_header(RDV_WITHDRAW) + src_vid + dst_vid + z


def create_GW_WITHDRAW(failed_gw, vid, dst):
    #print 'create_GW Withdraw', vid, dst, failed_gw
    fwd = struct.pack('!I', int(dst, 2))
    res = struct.pack('!HH', 0x0000, VIRO_CONTROL)
    src_vid = struct.pack("!I", int(vid, 2)) # Sender VID (32 bits)
    dst_vid = struct.pack("!I", int(dst, 2)) # Desitnation VID (32 bits)
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


# udpate the destination on the packet
def update_destination(packet, dst):
    header = packet[:16]
    sender = packet[16:20]
    payload = packet[24:]
    new_dest = struct.pack("!I", int(dst, 2))
    return (header + sender + new_dest + payload)


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


#  returns the opcode type for a packet
def get_op_code(packet):
    [op_code] = struct.unpack("!H", packet[14:16])

    return op_code


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
