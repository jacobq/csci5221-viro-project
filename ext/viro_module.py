import socket, struct, sys, time, random

from viro_veil import *


class ViroModule(object):
    def __init__(self, my_dpid, my_vid):
        self.dpid = my_dpid
        self.vid = my_vid
        self.L = len(my_vid)
        self.neighbors = {}
        self.rdv_store = {}
        self.rdv_request_tracker = {}
        self.routing_table = {}

    def update_routing_table_based_on_neighbor(self, neighbor_vid, port):
        print "update_routing_table_based_on_neighbor: neighbor_vid =", neighbor_vid, "port =", port
        bucket = delta(neighbor_vid, self.vid)
        # If we don't have any entries at this level -> create a new bucket list
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
        print "Recalculating default gateway for bucket",  bucket
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

        # DEBUG
        # print "min_distance =", min_distance, "min_entry =", min_entry
        # print "max_distance =", max_distance, "max_entry =", max_entry

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

    # Note: routing_table is a dictionary of k -> entries_list
    # where entries_list is a list of dictionaries
    # e.g. { 1: [{'gateway': ...}, {'gateway': ...}, ...], ...}
    def print_routing_table(self):
        print '\n----> Routing Table at :', self.vid, '|', self.dpid, ' <----'
        for distance in range(1, self.L + 1):
            if distance in self.routing_table and len(self.routing_table[distance]) > 0:
                for entry in self.routing_table[distance]:
                    print 'Bucket:', distance, \
                          'Port:', entry['port'], \
                          'Prefix:', entry['prefix'],\
                          'Gateway:', bin2str(entry['gateway'], self.L), \
                          'Next hop:', bin2str(entry['next_hop'], self.L), \
                          'Default:', entry['default']
            else:
                print 'Bucket:', distance, '--- E M P T Y ---'
        print 'RDV STORE: ', self.rdv_store, "\n"

    # This function reviews all the entries in the neighbor list and removes
    # entries that are expired (older than NEIGHBOR_EXPIRATION_TIME seconds)
    # It then calls remove_failed_next_hops_from_routing_table
    def remove_expired_neighbors(self):
        print "Now checking to see if any local links / neighbors have gone down"
        now = time.time()
        to_be_deleted = []
        for neighbor_vid, k_to_time in self.neighbors.items():
            for k, time_last_seen in k_to_time.items():
                delta_t = now - time_last_seen
                if delta_t >= NEIGHBOR_EXPIRATION_TIME:
                    print "Going to remove stale entry for neighbor", neighbor_vid, "at distance", k, "since delta_t =", delta_t
                    to_be_deleted.append({'vid': neighbor_vid, 'distance':k})
                else:
                    print "Keeping entry for neighbor", neighbor_vid, "at distance", k, "since delta_t =", delta_t

        self.remove_failed_next_hops_from_routing_table(to_be_deleted)
        # send RDV_WITHDRAW packets?
        for neighbor in to_be_deleted:
            del self.neighbors[neighbor['vid']][neighbor['distance']]

    def remove_failed_next_hops_from_routing_table(self, failed_next_hops):
        if len(failed_next_hops) < 1:
            print "No failed next hop entries to remove"
            return

        print "Now removing entries for failed next hops in routing table"
        for k, entries in self.routing_table.items():
            for entry_key, entry in enumerate(entries):
                next_hop = bin2str(entry['next_hop'], self.L)
                if next_hop not in self.neighbors or k not in self.neighbors[next_hop]:
                    print "Removing entry from routing table:", entry
                    del entries[entry_key]
                    self.recalculate_default_gw_for_bucket(k)

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
        dst = get_rdv_id(k, self.vid)
        packet = create_RDV_PUBLISH(bucket, self.vid, dst)

        print 'Node:', self.vid, 'is publishing neighbor', bin2str(bucket['next_hop'], self.L), 'to rdv:', dst
        return (packet, dst)

    def withdraw(self, failedNode, RDV_level):
        dst = get_rdv_id(RDV_level, self.vid)
        if dst != failedNode:
            packet = create_RDV_WITHDRAW(int(failedNode, 2), self.vid, '00')
            print 'Node: ', self.vid, 'is withdrawing neighbor', failedNode, 'to rdv:', dst

            return packet

    # FIXME: Not used?
    def withdraw_gw(self, failed_gw, vid, dst):
        print "Creating GW_WITHDRAW packet"
        packet = create_GW_WITHDRAW(failed_gw, vid, dst)

        print self.vid, '- RDV gateway withdraw:', failed_gw, 'to dst:', dst
        return packet

    def query(self, k):
        dst = get_rdv_id(k, self.vid)
        packet = create_RDV_QUERY(k, self.vid, dst)

        print 'Node:', self.vid, 'is querying to reach bucket:', k, 'to rdv:', dst
        return packet, dst

    def get_next_hop(self, dst_vid, is_query_or_publish=False):
        next_hop = None
        port = None

        while next_hop is None:
            distance = delta(self.vid, dst_vid)
            if distance == 0:
                break

            if distance in self.routing_table and len(self.routing_table[distance]) > 0:
                for entry in self.routing_table[distance]:
                    if entry['default']:
                        next_hop = str(entry['next_hop'])
                        port = int(entry['port'])
                        break
            if next_hop is not None:
                break

            # TODO: This code "smells" bad -- not sure if it's even doing anything important/correct
            if not is_query_or_publish:
                break

            print 'No next hop for destination: ', dst_vid, 'distance: ', distance

            # flip the distance bit to
            dst_vid = flip_bit(dst_vid, distance)

        if next_hop is None:
            print 'No route to destination', 'MyVID: ', self.vid, 'DEST: ', dst_vid

        return next_hop, port

    # Adds an entry to rdv_store, and also ensures that there are no duplicates
    def add_if_no_duplicate_rdv_entry(self, distance, new_entry):
        for x in self.rdv_store[distance]:
            if x[0] == new_entry[0] and x[1] == new_entry[1]:
                return
        self.rdv_store[distance].append(new_entry)

    # Adds an entry to rdv_store, and also ensures that there are no duplicates
    def add_if_no_duplicate_gw_entry(self, gw, new_entry):
        for x in self.rdv_request_tracker[gw]:
            if x == new_entry:
                return
        self.rdv_request_tracker[gw].append(new_entry)

    def process_rdv_publish(self, packet):
        src_vid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        next_hop = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)

        print "RDV_PUBLISH message received from: ", src_vid

        distance = delta(self.vid, next_hop)
        if distance not in self.rdv_store:
            self.rdv_store[distance] = []

        new_entry = [src_vid, next_hop]
        self.add_if_no_duplicate_rdv_entry(distance, new_entry)

    def process_rdv_query(self, packet):
        src_vid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)
        k = int(payload, 2)

        print "RDV_QUERY message received from: ", src_vid

        # search in rdv store for the logically closest gateway to reach kth distance away neighbor
        gw_str_list = self.find_gateways_in_rdv_store(k, src_vid)
        print "Got gw_str_list =", gw_str_list

        # if found then form the reply packet and send to src_vid
        if len(gw_str_list) < 1:
            # No gateway found
            print 'Node: ', self.vid, 'has no gateway for the rdv_query packet to reach bucket: ', k, 'for node: ', src_vid
            return ''

        gw_list = []
        for gw_str in gw_str_list:
            gw_list.append(int(gw_str,2))

        # create a RDV_REPLY packet and send it
        reply_packet = create_RDV_REPLY(gw_list, k, self.vid, src_vid)

        # Keeps track of the Nodes that requests each Gateways at 
        # specific level
        for gw_str in gw_str_list:
            if gw_str not in self.rdv_request_tracker:
                self.rdv_request_tracker[gw_str] = []
            self.add_if_no_duplicate_gw_entry(gw_str, src_vid)

        return reply_packet

    # k is an integer
    # src_vid is a string of '0's and '1's
    def find_gateways_in_rdv_store(self, k, src_vid):
        gw_dist = {}
        if k not in self.rdv_store:
            return []
        # Look through rdv store for next_hop entries
        # and build up a map/dictionary of gw_vid -> distance
        # (this eliminates the need to remove duplicates,
        # which might otherwise happen since a gateway may
        # have several edges connecting to a node in other subtree)
        for t in self.rdv_store[k]:
            gw_vid = t[0]
            distance = delta(gw_vid, src_vid)
            gw_dist[gw_vid] = distance

        gw_list = []
        for gw_vid, distance in gw_dist.items():
            gw_list.append({'gw_vid': gw_vid, 'distance': distance})

        if len(gw_list) < 1:
            return []

        # Sort the list of available gateways by distance (closest first)
        gw_list.sort(key=lambda gw: gw['distance'])
        # print "find_gateways_in_rdv_store found these gateways:", gw_list

        # Truncate list so that it has at most MAX_GW_PER_RDV_REPLY entries
        gw_list = gw_list[:MAX_GW_PER_RDV_REPLY]

        # Remove the distance information from the list so it's a list of VIDs again instead of a list of dictionaries
        gw_list = map(lambda x: x['gw_vid'], gw_list)
        return gw_list

    def process_rdv_reply(self, packet):
        # Fill my routing table using this new information
        [k] = struct.unpack("!I", packet[24:28])
        gw_offset = 28
        num_of_gw = (len(packet) - gw_offset)/4
        gw_list = struct.unpack("!" + "I"*num_of_gw, packet[28:(28+4*num_of_gw)])
        print "RDV_REPLY contained", num_of_gw, "gateway(s):", map(lambda s: bin2str(s, self.L), gw_list)
        for gw in gw_list:
            gw_str = bin2str(gw, self.L)

            if gw_str == self.vid:
                print "(Ignoring gateway in RDV_REPLY because it is us)"
                continue

            if not k in self.routing_table:
                self.routing_table[k] = []

            next_hop, port = self.get_next_hop_rdv(gw_str)
            if next_hop is None:
                print 'ERROR: no next_hop found for the gateway:', gw_str
                print "New routing information couldn't be added!"
                continue

            next_hop_int = int(next_hop, 2)
            bucket_info = {
                'prefix': get_prefix(self.vid, k),
                'gateway': gw,
                'next_hop': next_hop_int,
                'port': port
            }

            if not is_duplicate_bucket(self.routing_table[k], bucket_info):
                self.routing_table[k].append(bucket_info)
                self.recalculate_default_gw_for_bucket(k)

    def get_next_hop_rdv(self, gw_str):
        next_hop = None
        port = None

        distance = delta(self.vid, gw_str)
        if distance in self.routing_table:
            for entry in self.routing_table[distance]:
                if entry['default']:
                    next_hop = bin2str(entry['next_hop'], self.L)
                    port = str(entry['port'])

        return next_hop, port

    # Selects random entry from appropriate level bucket/entry in the routing table
    # Returns gateway and next hop as strings of '0's and '1's
    # and port as an integer
    def choose_gateway_for_forwarding_directive(self, dst_vid):
        print "Choosing gateway to use as forwarding directive for dst_vid =", dst_vid
        distance = delta(dst_vid, self.vid)
        if distance < 1:
            print "WARNING: choose_gateway_for_forwarding_directive was asked to get a gateway to reach ourselves"
        if distance in self.routing_table and len(self.routing_table[distance]) > 0:
            entries = self.routing_table[distance]
            random_index = random.randrange(0, len(entries))
            selected_entry = entries[random_index]
            print "Selected (random) gateway for forwarding directive:", selected_entry
            return bin2str(selected_entry['gateway'], L),\
                   bin2str(selected_entry['next_hop'], L),\
                   selected_entry['port']
        else:
            print "Could not find a gateway for distance =", distance, "for dst_vid=", dst_vid
            return None, None, None

    # FIXME: Not used?
    def process_rdv_withdraw(self, packet):
        print "WARNING: process_rdv_withdraw called but implementation not verified yet"
        src_vid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)

        print 'Node:', self.vid, 'has received process_rdv_withdraw from ', src_vid

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

        if self.vid != src_vid:  # only need to update routing table if this came from someone else
            self.remove_failed_gw(packet)  # update the Routing Table

        else:
            print "I am the rdv point. My routing table is already updated."

        return gw

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




