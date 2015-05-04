import socket, struct, sys, time, random

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
        print "update_routing_table_based_on_neighbor: neighbor_vid =", neighbor_vid, "port =", port
        bucket = delta(neighbor_vid, self.vid)
        # If we don't have any entries at this bucket -> create a new bucket
        if bucket not in self.routing_table:
            self.routing_table[bucket] = []

        bucket_info = {
            'prefix': get_prefix(self.vid, bucket),
            'gateway': int(self.vid, 2),
            'next_hop': int(neighbor_vid, 2),
            'port': port
        }

        if not is_duplicate_bucket(self.routing_table[bucket], bucket_info):
            self.routing_table[bucket].append(bucket_info)
            self.recalculate_default_gw_for_bucket(bucket)
        else:
            print "Ignoring duplicate routing entry", bucket_info

        print "Updating the Neighbors list..."
        self.update_neighbors(neighbor_vid, bucket)
        self.print_routing_table()

    # Presumably a gateway has just been added to or removed from the list for this bucket,
    # so we need to do the following:
    # - (Re)compute the logical distance of each gateway
    # - Set a gateway having minimal distance to be the default (and all others not to be the default)
    # - Limit the number of gateways stored to the maximum allowed
    #   as defined by MAX_GW_PER_LEVEL parameter (which is assumed to be > 1).
    #   To do that we remove a gateway whose distance is maximal,
    #   and which was not selected as the default (in the case of all gateways being equidistant)
    def recalculate_default_gw_for_bucket(self, bucket):
        print "Recalculating default gateway for bucket ",  bucket
        entries = self.routing_table[bucket]
        min_distance = float("inf")
        min_entry = None
        max_distance = -1
        max_entry = None
        for entry in entries:
            # Clear default flag -- will set again once all distances have been computed
            entry['default'] = False

            # Compute distance
            gw = bin2str(entry['gateway'], self.L)
            distance = delta(gw, self.vid)

            # Update min/max pointers
            if distance > max_distance:
                max_distance = distance
                max_entry = entry
            if distance < min_distance:
                min_distance = distance
                min_entry = entry

        if min_entry is None or max_entry is None:
            print "recalculate_default_gw_for_bucket did not find a min and max distance gateways (no gateways)"
            return

        print "min_distance =", min_distance, "min_entry =", min_entry
        print "max_distance =", max_distance, "max_entry =", max_entry

        # Set (possibly new) default gateway for this bucket to be one having minimal distance
        min_entry['default'] = True

        # Limit number of entries (assume for now that there will be at most 1 too many)
        if len(entries) > MAX_GW_PER_LEVEL:
            max_gw_index = entries.index(max_entry)
            if not max_entry['default']:
                # Delete gateway at maximal distance (non-equidistant case)
                del entries[max_gw_index]
            else:
                # max_distance == min_distance (equidistant case)
                # So just delete any non-default gateway
                next_gw_index = (max_gw_index + 1) % len(entries)
                del entries[next_gw_index]

        # In case somehow there were more than 1 too many gateways then do this again.
        # If this were expected to happen often then we could do something more efficient for that case,
        # such as sort the entries in order of increasing distance then removing all beyond maximum,
        # but this is not expected to happen. We just have this check here to ensure correctness in case
        # of this unexpected scenario where there is more than 1 gateway that needs to be removed
        # (since this function should be called each time a gateway is added or removed).
        if len(entries) > MAX_GW_PER_LEVEL:
            print "WARNING: Recursively calling recalculate_default_gw_for_bucket; unexpected situation"
            self.recalculate_default_gw_for_bucket(bucket)



    def update_neighbors(self, neighbor_vid, distance):
        if neighbor_vid not in self.neighbors:
            self.neighbors[neighbor_vid] = {}
        self.neighbors[neighbor_vid][distance] = time.time()


    def print_routing_table(self):
        print '\n----> Routing Table at :', self.vid, '|', self.dpid, ' <----'
        for distance in range(1, self.L + 1):
            if distance in self.routing_table:
                for entry in self.routing_table[distance]:
                    print 'Bucket:', distance, \
                          'Port:', entry['port'], \
                          'Prefix:', entry['prefix'],\
                          'Gateway:', bin2str(entry['gateway'], self.L), \
                          'Next hop:', bin2str(entry['next_hop'], self.L), \
                          'Default:', entry['default']
            else:
                print 'Bucket::', distance, '--- E M P T Y ---'
        print 'RDV STORE: ', self.rdv_store, "\n"


    def remove_failed_gw(self, packet, gw=None):
        if gw is None:
            payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)
            payload = int(payload, 2)
        else:
            payload = int(gw, 2)

        to_be_deleted = {}
        for level in self.routing_table:
            to_be_deleted[level] = []
            for idx in xrange(0, len(self.routing_table[level])):
                entry = self.routing_table[level][idx]
                if entry['gateway'] == payload or entry['next_hop'] == payload:
                    to_be_deleted[level].append(idx)

        for level in to_be_deleted:
            for index in to_be_deleted[level]:
                del self.routing_table[level][index]

        bucket_ = []
        for level in self.routing_table:
            if len(self.routing_table[level]) == 0:
                bucket_.append(level)

        for level in bucket_:
            del self.routing_table[level]

        return


    def publish(self, bucket, k):
        dst = get_rendezvous_id(k, self.vid)
        packet = create_RDV_PUBLISH(bucket, self.vid, dst)

        print 'Node :', self.vid, 'is publishing neighbor', bin2str(bucket['next_hop'], self.L), 'to rdv:', dst
        return (packet, dst)


    def withdraw(self, failedNode, RDV_level):
        dst = get_rendezvous_id(RDV_level, self.vid)
        if dst != failedNode:
            packet = create_RDV_WITHDRAW(int(failedNode, 2), self.vid, '00')
            print 'Node : ', self.vid, 'is withdrawing neighbor', failedNode, 'to rdv:', dst

            return packet


    # FIXME: Not used?
    def withdraw_gw(self, failed_gw, vid, dst):
        print "Creating GW_WITHDRAW packet"
        packet = create_GW_WITHDRAW(failed_gw, vid, dst)

        print self.vid, ' - RDV Gateway WithDraw:', failed_gw, 'to dst:', dst
        return packet


    def query(self, k):
        dst = get_rendezvous_id(k, self.vid)
        packet = create_RDV_QUERY(k, self.vid, dst)

        print 'Node :', self.vid, ' is quering to reach Bucket :', k, 'to rdv:', dst
        return (packet, dst)


    def get_next_hop(self, packet):
        dst_vid = get_dest(packet, self.L)
        next_hop = ''
        packet_type = get_operation(packet)
        port = ''

        while next_hop == '':

            distance = delta(self.vid, dst_vid)
            if distance == 0:
                break

            if distance in self.routing_table:
                if len(self.routing_table[distance]) > 0:
                    # TODO: Will need to modify so that this doesn't just take the first entry every time
                    next_hop = str(self.routing_table[distance][0]['next_hop'])
                    port = int(self.routing_table[distance][0]['port'])
                    break

            if (packet_type != RDV_PUBLISH) and (packet_type != RDV_QUERY):
                break

            print 'No next hop for destination: ', dst_vid, 'distance: ', distance

            # flip the distance bit to
            dst_vid = flip_bit(dst_vid, distance)

        if next_hop == '':
            print 'No route to destination', 'MyVID: ', self.vid, 'DEST: ', dst_vid
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


    def process_rdv_publish(self, packet):
        src_vid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)

        print "RDV_PUBLISH message received from: ", src_vid

        distance = delta(self.vid, payload)
        if distance not in self.rdv_store:
            self.rdv_store[distance] = []

        new_entry = [src_vid, payload]
        self.add_if_no_duplicate_rdv_entry(distance, new_entry)

        return


    def process_rvd_query(self, packet):
        src_vid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)
        k = int(payload, 2)

        print "RDV_QUERY message received from: ", src_vid

        # search in rdv store for the logically closest gateway to reach kth distance away neighbor
        gw = self.find_a_gw(k, src_vid)

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


    def process_self_rvd_query(self, packet):
        src_vid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)

        k = int(payload, 2)

        # search in rdv store for the logically closest gateway to reach kth distance away neighbor
        gw_str = self.find_a_gw(k, src_vid)

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

        # Destination Subtree-k
        bucket_info = {
            'prefix': get_prefix(self.vid, k),
            'gateway': int(gw_str, 2),
            'next_hop': int(next_hop, 2),
            'port': port
        }
        self.routing_table[k] = []
        self.routing_table[k].append(bucket_info)
        self.recalculate_default_gw_for_bucket(k)


    def process_rdv_reply(self, packet):
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
            print "New routing information couldn't be added!"
            return

        next_hop_int = int(next_hop, 2)
        bucket_info = {
            'prefix': get_prefix(self.vid, k),
            'gateway': gw,
            'next_hop': next_hop_int,
            'port': port
        }

        self.routing_table[k] = []
        self.routing_table[k].append(bucket_info)
        self.recalculate_default_gw_for_bucket(k)

    # FIXME: Not used?
    def process_rdv_withdraw(self, packet):
        src_vid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)

        print 'Node :', self.vid, 'has received process_rdv_withdraw from ', src_vid

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


    def find_a_gw(self, k, src_vid):
        gw = {}
        if k not in self.rdv_store:
            return ''
        for t in self.rdv_store[k]:
            distance = delta(t[0], src_vid)
            if distance not in gw:
                gw[distance] = t[0]
            gw[distance] = t[0]
        if len(gw) == 0:
            return ''
        s = gw.keys()
        s.sort()

        return gw[s[0]]


    # TODO: Dead code -- may be incorrect
    def get_gw_list(self, next_hop):
        print 'FIXME: get_gw_list should not be called yet -- implementation may not be correct'
        gw_list = []
        # calculate logical distance
        print "Finding the gateways..."
        entries = self.find_entries_with_neighbor_as_next_hop(next_hop)
        for level in entries:
            if level != 1 or level != -1:
                bucket = entries[level]
                # return gateway from routing_table with distance = bucket
                gw = bin2str(self.routing_table[level][bucket]['gateway'], self.L)
                gw_list.append(gw)

        return gw_list


    # Returns a dictionary that is like a copy of the routing table except:
    # - There is exactly 1 entry for each bucket
    # - If the next hop in a routing table entry matches this neighbor_vid
    #   then that entry is copied into this dictionary
    # - Otherwise (e.g. no matching entry found for bucket/level) the corresponding entry is set to -1
    # TODO: Dead code -- may be incorrect
    def find_entries_with_neighbor_as_next_hop(self, neighbor_vid):
        print 'FIXME: find_entries_with_neighbor_as_next_hop should not be called yet -- implementation may not be correct'
        # Note: removed dead code from original implementation (may need to add back later when needed)
        result = {}
        for bucket in self.routing_table:
            result[bucket] = -1
            for entry in self.routing_table[bucket]:
                next_hop = bin2str(self.routing_table[bucket][entry]['next_hop'], self.L)
                if next_hop == neighbor_vid:
                    result[bucket] = entry

        return result


    def get_next_hop_rdv(self, dst_vid_str):
        next_hop = ''
        port = ''

        distance = delta(self.vid, dst_vid_str)
        if distance in self.routing_table:
            next_hop = bin2str(self.routing_table[distance][0]['next_hop'], self.L)
            port = str(self.routing_table[distance][0]['port'])

        return (next_hop, port)

