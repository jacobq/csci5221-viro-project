#!/usr/bin/python

from viro_veil import extractARPDstMac
import socket, struct, sys, time, random
# Local imports 
from viro_veil import * # for the constants.


class viroModule(object):
  
    def __init__(self, mydpid, myvid):
        self.mydpid = mydpid
        self.myvid = myvid
        self.L = len(myvid)
        self.routingTable = {}
        self.rdvStore = {}
        self.neigbhors = {}
        self.rdvRequestTracker = {} 

     
    ###############################################
       #   Neighbour discovering
    ###############################################
    def updateRoutingTable(self, vid, port):
  

			# update my routing table
			# myvid: my own VID
			# vid: my neibhour VID 
			# port number information
			
			
			# Routing table is a dictionary, it contains the values at each distances from 1 to L
			# So key in the routing table is the bucket distance, value is the 3 tuple: tuple 1 = nexthop (vid), tuple 2 = gateway (vid), tuple 3 = prefix (string)
			
			
			# Learn L, it is the length of any vid
			myprintid = "VEIL_SWITCH: ["+self.mydpid+'|'+self.myvid+']'
			
			
			dist = delta(vid,self.myvid)
			     
			if dist not in self.routingTable:
			      self.routingTable[dist] = []
			
			bucket_len = len(self.routingTable[dist])
			#Changed logic
			bucket_info = [int(vid,2), int(self.myvid,2), port, getPrefix(self.myvid,dist)]
			
			if not isDuplicateBucket(self.routingTable[dist], bucket_info):
				  self.routingTable[dist].append(bucket_info)
			
			 
			# Saving the information in the neigbhors table.
			print "Updating the Neigbhors list..."
			self.updateNeigbhors(vid, dist)
			
			 
			# Printing routing table 
			print '\n\t----> Routing Table at :',self.myvid,'|',self.mydpid,' <----'
			
			for i in range(1,self.L+1):
			   if i in self.routingTable:
			      for j in self.routingTable[i]:
			          print 'Bucket::', i, 'Nexthop:',bin2str(j[0],self.L),'Port:',j[2], 'Gateway:',bin2str(j[1],self.L), 'Prefix:',j[3]
			   else:
			          print 'Bucket::',i,'  --- E M P T Y --- '
			print 'RDV STORE: ', self.rdvStore
			print '\n --  --  --  --  -- --  --  --  --  -- --  --  --  --  -- \n'  
			  
  
    ###############################################
      #    Publish function starts here
    ###############################################




    ###############################################
      #   removeFailedGW function starts here
    ###############################################

    def removeFailedGW(self, packet, gw = None):

        if gw == None:
            payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)
            payload = int(payload, 2)
        else:
            payload = int(gw,2)             

        
        delete = {}
        for level in self.routingTable:
          delete[level] = []
          for idx in xrange(0, len(self.routingTable[level])):
            entry = self.routingTable[level][idx]
            if entry[1]==payload or entry[0] == payload: # Remove if either gateway or nextHop failed
              delete[level].append(idx)
                    
        for index in delete:
			    for lis in delete[index]:
					del self.routingTable[index][lis]
         
        bucket_ = []
        for level in self.routingTable:
				if len(self.routingTable[level]) == 0:
					bucket_.append(level)
       
        for index in bucket_:
				del self.routingTable[index]

        return

    ###############################################
      #   removeFailedGW function starts here
    ###############################################





    ###############################################
      #   updateNeigbors function starts here
    ###############################################

    def updateNeigbhors(self, nvid, dist):

        if nvid not in self.neigbhors:
            self.neigbhors[nvid] = {}
     
        self.neigbhors[nvid][dist] = time.time()

    
    def findEntry(self, nvid, bucket = None):
         
        # into the neigbhours table during neibhors discovering process.
        if bucket != None:
           index = ''
           n = len(self.routingTable[bucket])

           for i in range(0, n):
             print self.routingTable[bucket][i]
             nextHop = bin2str(self.routingTable[bucket][i][0],self.L)
             if nextHop == nvid:
                 index = i
                 break
        else:

            index = {}
            for level in self.routingTable:
               index[level] = -1
               for idx in xrange(0, len(self.routingTable[level])):
                   
                   nextHop = bin2str(self.routingTable[level][idx][0],self.L)
                   if nextHop == nvid:
                      index[level] = idx
                             
        return index

    ###############################################
      #  updateNeigbors function starts here
    ###############################################



    def publish(self,bucket,k):

        dst = getRendezvousID(k,self.myvid)
        packet = createRDV_PUBLISH(bucket,self.myvid,dst)

        print 'Node :',self.myvid, ' is publishing neighbor', bin2str(bucket[0],self.L), 'to rdv:',dst
        return (packet,dst)
       

    ###############################################
       #    Publish FUNCTION ENDS HERE
    ###############################################


    ###############################################
       #  withdraw FUNCTION STARTS HERE
    ###############################################

    def withdraw(self,failedNode,RDV_level):
       
         dst = getRendezvousID(RDV_level, self.myvid)
         if dst != failedNode:

             packet = createRDV_WITHDRAW(int(failedNode,2), self.myvid, '00')
             print 'Node : ', self.myvid, 'is withdrawing neighbor', failedNode, 'to rdv:',dst
        
             return packet

    ###############################################
         # withdraw function ENDS here
    ###############################################


    ###############################################
         #    Query function starts here
    ###############################################
    def query(self,k):

        dst = getRendezvousID(k,self.myvid)
        packet = createRDV_QUERY(k,self.myvid,dst)

        print 'Node :', self.myvid, ' is quering to reach Bucket :',k, 'to rdv:',dst
        return (packet,dst)

    ###############################################  
            #    Query FUNCTION ENDS HERE
    ###############################################




    ###############################################
         # getNextHop function starts here
    ###############################################
    def getNextHop(self, packet):
        #global routingTable
        
        dst = getDest(packet,self.L)  
        nexthop = ''
        packettype = getOperation(packet)
        port = ''
        
        
        while nexthop == '': 
     
           dist = delta(self.myvid,dst)
           if dist == 0:
              break

           if dist in self.routingTable: 
              if len(self.routingTable[dist]) > 0 : 
                nexthop = str(self.routingTable[dist][0][0])
                port = int(self.routingTable[dist][0][2])
                break

           if (packettype != RDV_PUBLISH) and (packettype != RDV_QUERY):
              break 
        
           print 'No next hop for destination: ',dst,'dist: ', dist

           # flip the dist bit to
           dst = flipBit(dst,dist)
  
         
        if nexthop == '':
            print 'No route to destination' ,'MyVID: ', self.myvid, 'DEST: ', dst
            return ('','')

        return (nexthop, port)
    ###############################################  
            #  getNextHop FUNCTION ENDS HERE
    ###############################################



    ########################################################
         # addIfNODuplicateRDVENTRY  function starts here
    ########################################################

    # Adds an entry to rdvStore, and also ensures that there are no duplicates
    def addIfNODuplicateRDVENTRY(self,dist,newentry):

        for x in self.rdvStore[dist]:
            if x[0] == newentry[0] and x[1] == newentry[1]:
                   return
        self.rdvStore[dist].append(newentry)
    

    
     # Adds an entry to rdvStore, and also ensures that there are no duplicates
    def addIfNODuplicateGWENTRY(self, gw,newentry):

        for x in self.rdvRequestTracker[gw]:
            if x == newentry :
               return
        self.rdvRequestTracker[gw].append(newentry)

    ######################################################
         # addIfNODuplicateRDVENTRY FUNCTION ENDS HERE
    ######################################################



    ######################################################
         # rdvPublish FUNCTION ENDS HERE
    ######################################################
    
    def rdvPublish(self, packet):
                 
        svid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)

        print "RDV_PUBLISH message received from: ", svid

        dist = delta(self.myvid,payload)
        if dist not in self.rdvStore:
            self.rdvStore[dist] = []

        newentry = [svid,payload]
        self.addIfNODuplicateRDVENTRY(dist,newentry)

        return
     
    ######################################################
         # rdvPublish FUNCTION ENDS HERE
    ######################################################



    ######################################################
         # rdvQuery STARTS HERE
    ######################################################

    def rvdQuery(self, packet):
        
        svid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)
        k = int(payload,2)

        print "RDV_QUERY message received from: ", svid

        # search in rdv store for the logically closest gateway to reach kth distance away neighbor
        gw = self.findAGW(self.rdvStore,k,svid)

        # if found then form the reply packet and send to svid
        if gw == '':
            # No gateway found
            print 'Node : ',self.myvid, 'has no gateway for the rdv_query packet to reach bucket: ',k,' for node: ', svid
            return ''

        # create a RDV_REPLY packet and send it
        replypacket = createRDV_REPLY(int(gw,2),k, self.myvid, svid)
   


        # Keeps track of the Nodes that requests each Gateways at 
        # specific level

        if gw not in self.rdvRequestTracker:
              self.rdvRequestTracker[gw] = []

        self.addIfNODuplicateGWENTRY(gw, svid)

        return replypacket

     
    ######################################################
         # rdvQuery FUNCTION ENDS HERE
    ######################################################


    
    ######################################################
         # findAGW and getGW FUNCTION STARTS HERE
    ######################################################


    def findAGW(self, rdvStore,k,svid):    
        gw = {}
        if k not in rdvStore:
           return ''
        for t in rdvStore[k]:
           r = delta(t[0],svid)
           if r not in gw:
             gw[r] = t[0]
           gw[r] = t[0]
        if len(gw) == 0:
           return ''
        s = gw.keys()
        s.sort()

        return gw[s[0]]


    def getGW(self, nexthop):

        gwList  = []
        # calculate logical distance
        
        print "Finding the gateways..."
        index = self.findEntry(nexthop)

        for level in index:
            if level != 1 or level != -1 :
               bucket = index[level]  
               
               # return gateway from routingTable with dist = bucket
               gw = bin2str(self.routingTable[level][bucket][1], self.L)
               gwList.append(gw)

        return gwList      

    ######################################################
         # findAGW and getGW FUNCTION ENDS HERE
    ######################################################



    ######################################################
         # rdvReply FUNCTION ENDS HERE
    ######################################################

    def rdvReply(self, packet):
        

        # Fill my routing table using this new information
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)
        [gw] = struct.unpack("!I", packet[28:32])
        gw_str = bin2str(gw, self.L)
        k = int(payload,2)

        if k in self.routingTable:
            print 'Node :',self.myvid, ' has already have an entry to reach neighbors at distance - ',k
            return

        nexthop, port = self.getNextHopRDV(gw_str)
        if nexthop == '':
            print 'ERROR: no nexthop found for the gateway:',gw_str
            print 'New routing information couldnt be added! '
            return

        nh = int(nexthop,2)
        bucket_info = [nh, gw, port, getPrefix(self.myvid,k)]

        self.routingTable[k] = []
        self.routingTable[k].append(bucket_info)
       
        
    ######################################################
        # rdvReply FUNCTION ENDS HERE
    ######################################################
   


    ###############################################
         #    getNextHopRDV function starts here
    ###############################################

    def getNextHopRDV(self, destvid_str):
        nexthop = ''
        port = ''

        dist = delta(self.myvid,destvid_str)
        if dist in self.routingTable:
           nexthop = bin2str(self.routingTable[dist][0][0],self.L)
           port = str(self.routingTable[dist][0][2])

        return (nexthop, port)
    
    ###############################################
          #    getNextHopRDV FUNCTION ENDS HERE
    ##############################################




    ###############################################
         #    selfRVDQuery function starts here
    ###############################################

    def selfRVDQuery(self, packet):


        svid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)

        k = int(payload,2)

        # search in rdv store for the logically closest gateway to reach kth distance away neighbor
        gw_str = self.findAGW(self.rdvStore,k,svid)

        # if found then form the reply packet and send to svid
        if gw_str == '':
            # No gateway found
            print 'Node :', self.myvid, 'has no gateway for the rdv_query packet to reach bucket: ',k,' for node: ', svid
            return ''
   
        
        if k in self.routingTable:
            print 'Node :',self.myvid, 'has already have an entry to reach neighbors at distance: ',k
            return


        nexthop, port = self.getNextHopRDV(gw_str)
        if nexthop == '':
            print 'No nexthop found for the gateway:',gw_str
            print 'New routing information couldnt be added! '
            return

        nh = int(nexthop,2)

        # Destination Subtree-k
        gw = int(gw_str, 2)
        bucket_info = [nh, gw, port, getPrefix(self.myvid,k)]

        self.routingTable[k] = []
        self.routingTable[k].append(bucket_info)

    ###############################################
          #  selfRVDQuery FUNCTION ENDS HERE
    ##############################################



    ###############################################
         #  rdvWithDraw function starts here
    ###############################################

    def rdvWithDraw(self, packet):
        
        svid = bin2str((struct.unpack("!I", packet[16:20]))[0], self.L)
        payload = bin2str((struct.unpack("!I", packet[24:28]))[0], self.L)
      
        print 'Node :',self.myvid, 'has received rdv_withdraw from ', svid

        gw = {}
        print self.rdvStore
        for level in self.rdvStore:
            delete = []            
            for idx in range(0, len(self.rdvStore[level])):
 
                entry = self.rdvStore[level][idx]

                if (entry[0]==payload) or (entry[1] == payload):
                    
                    delete.append(idx)          

                    # Save the list of Removed Gateways and delete them from rdv Store
                    if not level in gw:
                         gw[level] = []
                     
                    gw[level].append(entry[0]) # saves the removed GWs
             
            for index in delete:
					del self.rdvStore[level][index]
     
        
        if self.myvid != svid: # I am the rvd itself: no need to update routing table.
            self.removeFailedGW(packet)  # update the Routing Table
      
        else:
			    print "I am the rdv point. My routing table is already updated."

        return  gw

    ###############################################
          # rdvWithDraw FUNCTION ENDS HERE
    ##############################################


    ###############################################
         #    Query function starts here
    ###############################################
    def rdvGWithDraw(self, failedGW, myvid, dst):

        print "Creating GW_WITHDRAW packet"
        packet = createGW_WITHDRAW(failedGW,myvid,dst)

        print self.myvid, ' - RDV Gateway WithDraw:',failedGW, 'to dst:',dst
        return packet

    ###############################################  
            #    Query FUNCTION ENDS HERE
    ###############################################
