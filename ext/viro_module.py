#!/usr/bin/python

from viro_veil import extract_arp_dst_mac
import socket, struct, sys, time, random
# Local imports 
from viro_veil import *  # for the constants


class ViroModule(object):
    def __init__(self, my_dpid, my_vid):
        self.dpid = my_dpid
        self.vid = my_vid
        self.L = len(my_vid)
        self.routing_table = {}
        self.rdv_store = {}
        self.neighbors = {}
        self.rdv_request_tracker = {}


    def update_routing_table_based_on_neighbor(self, neighbor_vid, port):
        print "update_routing_table_based_on_neighbor", neighbor_vid, port
        distance = delta(neighbor_vid, self.vid)
        # If we don't have any entries at this distance -> create a new bucket
        if distance not in self.routing_table:
            self.routing_table[distance] = []

        bucket_info = {
            'port': port,
            'prefix': get_prefix(self.vid, distance),
            'gateway': int(self.vid, 2),
            'next_hop': int(neighbor_vid, 2),
            'default': True
        }

        if not is_duplicate_bucket(self.routing_table[distance], bucket_info):
            self.routing_table[distance].append(bucket_info)
        else:
            print "Ignoring duplicate routing entry", bucket_info

        print "Updating the Neighbors list..."
        self.update_neighbors(neighbor_vid, distance)
        self.print_routing_table()


    def update_neighbors(self, neighbor_vid, distance):
        if neighbor_vid not in self.neighbors:
            self.neighbors[neighbor_vid] = {}
        self.neighbors[neighbor_vid][distance] = time.time()


    def print_routing_table(self):
        print '\n----> Routing Table at :', self.vid, '|', self.dpid, ' <----'
        for distance in range(1, self.L + 1):
            if distance in self.routing_table:
                for entry in self.routing_table[distance]:
                    print 'Bucket::', distance, \
                          'Port:', entry['port'], \
                          'Prefix:', entry['prefix'],\
                          'Gateway:', bin2str(entry['gateway'], self.L), \
                          'Next hop:', bin2str(entry['next_hop'], self.L), \
                          'Default:', entry['default']
            else:
                print 'Bucket::', distance, '--- E M P T Y ---'
        print 'RDV STORE: ', self.rdv_store
        print '\n--  --  --  --  --  --  --  --  --  --  --  --  --  --  --\n'


    def remove_failed_gw(self, packet, gw=None):
        if gw == None:
            payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)
            payload = int(payload, 2)
        else:
            payload = int(gw, 2)

        delete = {}
        for level in self.routing_table:
            delete[level] = []
            for idx in xrange(0, len(self.routing_table[level])):
                entry = self.routing_table[level][idx]
                if entry['gateway'] == payload or entry['next_hop'] == payload:  # Remove if either gateway or nextHop failed
                    delete[level].append(idx)

        for index in delete:
            for lis in delete[index]:
                del self.routing_table[index][lis]

        bucket_ = []
        for level in self.routing_table:
            if len(self.routing_table[level]) == 0:
                bucket_.append(level)

        for index in bucket_:
            del self.routing_table[index]

        return


    def find_entry(self, nvid, bucket=None):
        # into the neighbors table during neighbor discovery process.
        if bucket != None:
            index = ''
            n = len(self.routing_table[bucket])

            for i in range(0, n):
                print self.routing_table[bucket][i]
                next_hop = bin2str(self.routing_table[bucket][i]['next_hop'], self.L)
                if next_hop == nvid:
                    index = i
                    break
        else:

            index = {}
            for level in self.routing_table:
                index[level] = -1
                for idx in xrange(0, len(self.routing_table[level])):
                    next_hop = bin2str(self.routing_table[level][idx]['next_hop'], self.L)
                    if next_hop == nvid:
                        index[level] = idx

        return index


    def publish(self, bucket, k):
        dst = get_rendezvous_id(k, self.vid)
        packet = create_RDV_PUBLISH(bucket, self.vid, dst)

        print 'Node :', self.vid, ' is publishing neighbor', bin2str(bucket[0], self.L), 'to rdv:', dst
        return (packet, dst)



    def withdraw(self, failedNode, RDV_level):
        dst = get_rendezvous_id(RDV_level, self.vid)
        if dst != failedNode:
            packet = create_RDV_WITHDRAW(int(failedNode, 2), self.vid, '00')
            print 'Node : ', self.vid, 'is withdrawing neighbor', failedNode, 'to rdv:', dst

            return packet


    def query(self, k):
        dst = get_rendezvous_id(k, self.vid)
        packet = create_RDV_QUERY(k, self.vid, dst)

        print 'Node :', self.vid, ' is quering to reach Bucket :', k, 'to rdv:', dst
        return (packet, dst)


    def get_next_hop(self, packet):
        # global routing_table

        dst = get_dest(packet, self.L)
        next_hop = ''
        packet_type = get_operation(packet)
        port = ''

        while next_hop == '':

            distance = delta(self.vid, dst)
            if distance == 0:
                break

            if distance in self.routing_table:
                if len(self.routing_table[distance]) > 0:
                    next_hop = str(self.routing_table[distance][0]['next_hop'])
                    port = int(self.routing_table[distance][0]['port'])
                    break

            if (packet_type != RDV_PUBLISH) and (packet_type != RDV_QUERY):
                break

            print 'No next hop for destination: ', dst, 'distance: ', distance

            # flip the distance bit to
            dst = flip_bit(dst, distance)

        if next_hop == '':
            print 'No route to destination', 'MyVID: ', self.vid, 'DEST: ', dst
            return ('', '')

        return (next_hop, port)


    # Adds an entry to rdv_store, and also ensures that there are no duplicates
    def add_if_no_duplicate_rdv_entry(self, distance, newentry):
        for x in self.rdv_store[distance]:
            if x[0] == newentry[0] and x[1] == newentry[1]:
                return
        self.rdv_store[distance].append(newentry)


    # Adds an entry to rdv_store, and also ensures that there are no duplicates
    def add_if_no_duplicate_gw_entry(self, gw, new_entry):
        for x in self.rdv_request_tracker[gw]:
            if x == new_entry:
                return
        self.rdv_request_tracker[gw].append(new_entry)


    def rdv_publish(self, packet):
        src_vid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)

        print "RDV_PUBLISH message received from: ", src_vid

        distance = delta(self.vid, payload)
        if distance not in self.rdv_store:
            self.rdv_store[distance] = []

        new_entry = [src_vid, payload]
        self.add_if_no_duplicate_rdv_entry(distance, new_entry)

        return


    def rvd_query(self, packet):
        src_vid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)
        k = int(payload, 2)

        print "RDV_QUERY message received from: ", src_vid

        # search in rdv store for the logically closest gateway to reach kth distance away neighbor
        gw = self.find_a_gw(self.rdv_store, k, src_vid)

        # if found then form the reply packet and send to src_vid
        if gw == '':
            # No gateway found
            print 'Node : ', self.vid, 'has no gateway for the rdv_query packet to reach bucket: ', k, ' for node: ', src_vid
            return ''

        # create a RDV_REPLY packet and send it
        reply_packet = create_RDV_REPLY(int(gw, 2), k, self.vid, src_vid)

        # Keeps track of the Nodes that requests each Gateways at 
        # specific level

        if gw not in self.rdv_request_tracker:
            self.rdv_request_tracker[gw] = []

        self.add_if_no_duplicate_gw_entry(gw, src_vid)

        return reply_packet

    def find_a_gw(self, rdv_store, k, src_vid):
        gw = {}
        if k not in rdv_store:
            return ''
        for t in rdv_store[k]:
            r = delta(t[0], src_vid)
            if r not in gw:
                gw[r] = t[0]
            gw[r] = t[0]
        if len(gw) == 0:
            return ''
        s = gw.keys()
        s.sort()

        return gw[s[0]]


    def get_gw(self, next_hop):

        gw_list = []
        # calculate logical distance

        print "Finding the gateways..."
        index = self.find_entry(next_hop)

        for level in index:
            if level != 1 or level != -1:
                bucket = index[level]
                # return gateway from routing_table with distance = bucket
                gw = bin2str(self.routing_table[level][bucket]['gateway'], self.L)
                gw_list.append(gw)

        return gw_list


    def rdv_reply(self, packet):
        # Fill my routing table using this new information
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)
        [gw] = struct.unpack("!I", packet[28:32])
        gw_str = bin2str(gw, self.L)
        k = int(payload, 2)

        if k in self.routing_table:
            print 'Node :', self.vid, ' has already have an entry to reach neighbors at distance - ', k
            return

        next_hop, port = self.get_next_hop_rdv(gw_str)
        if next_hop == '':
            print 'ERROR: no next_hop found for the gateway:', gw_str
            print 'New routing information couldnt be added! '
            return

        next_hop_int = int(next_hop, 2)
        bucket_info = [next_hop_int, gw, port, get_prefix(self.vid, k)]

        self.routing_table[k] = []
        self.routing_table[k].append(bucket_info)


    def get_next_hop_rdv(self, dst_vid_str):
        next_hop = ''
        port = ''

        distance = delta(self.vid, dst_vid_str)
        if distance in self.routing_table:
            next_hop = bin2str(self.routing_table[distance][0]['next_hop'], self.L)
            port = str(self.routing_table[distance][0]['port'])

        return (next_hop, port)


    def self_rvd_query(self, packet):
        src_vid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)

        k = int(payload, 2)

        # search in rdv store for the logically closest gateway to reach kth distance away neighbor
        gw_str = self.find_a_gw(self.rdv_store, k, src_vid)

        # if found then form the reply packet and send to src_vid
        if gw_str == '':
            # No gateway found
            print 'Node :', self.vid, 'has no gateway for the rdv_query packet to reach bucket: ', k, ' for node: ', src_vid
            return ''

        if k in self.routing_table:
            print 'Node :', self.vid, 'has already have an entry to reach neighbors at distance: ', k
            return

        next_hop, port = self.get_next_hop_rdv(gw_str)
        if next_hop == '':
            print 'No next_hop found for the gateway:', gw_str
            print 'New routing information couldnt be added! '
            return

        next_hop_int = int(next_hop, 2)

        # Destination Subtree-k
        gw = int(gw_str, 2)
        bucket_info = [next_hop_int, gw, port, get_prefix(self.vid, k)]

        self.routing_table[k] = []
        self.routing_table[k].append(bucket_info)

    def rdv_withdraw(self, packet):
        src_vid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)

        print 'Node :', self.vid, 'has received rdv_withdraw from ', src_vid

        gw = {}
        print self.rdv_store
        for level in self.rdv_store:
            delete = []
            for idx in range(0, len(self.rdv_store[level])):

                entry = self.rdv_store[level][idx]

                if (entry[0] == payload) or (entry[1] == payload):

                    delete.append(idx)

                    # Save the list of Removed Gateways and delete them from rdv Store
                    if not level in gw:
                        gw[level] = []

                    gw[level].append(entry[0])  # saves the removed GWs

            for index in delete:
                del self.rdv_store[level][index]

        if self.vid != src_vid:  # I am the rvd itself: no need to update routing table.
            self.remove_failed_gw(packet)  # update the Routing Table

        else:
            print "I am the rdv point. My routing table is already updated."

        return gw


    def rdv_gw_withdraw(self, failed_gw, vid, dst):
        print "Creating GW_WITHDRAW packet"
        packet = create_GW_WITHDRAW(failed_gw, vid, dst)

        print self.vid, ' - RDV Gateway WithDraw:', failed_gw, 'to dst:', dst
        return packet