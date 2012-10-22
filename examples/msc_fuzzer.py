#!/usr/bin/env python

import sys

from scapy.packet import Raw, fuzz
from USBFuzz.MSC import *

arg = sys.argv[1].split(':')
dev = BOMSDevice(arg[0], arg[1], timeout=1200)

# make sure pipe is clear
dev.boms_reset()

# Read Capacity to get blocksize
cmd = MSCCBW()/SCSICmd()/ReadCapacity10()
#cmd.show2()
#print dev.hex_dump(str(cmd))
dev.send(cmd)
reply = dev.read_reply()
dev.check_status(reply) 
if Raw in reply and len(reply[Raw]) == 8:
    data = str(reply[Raw])
    max_lba = struct.unpack(">I", data[:4])[0]
    block_size = struct.unpack(">I", data[4:])[0]
else:
    reply.show()
    sys.exit()

print "Device is %uMb, max LBA is %x and blocksize is %x" % (round(float(max_lba*block_size)/1048576), max_lba, block_size)

opcode = 0x95
while dev is not None:
    try:
        opcode += 1        
        test = 0
        while test<100:
            test += 1

            r = struct.unpack("I", os.urandom(4))[0]
            print "\nSending command %u with random value %x" % (dev.cur_tag() + 1, r)
            cmd = MSCCBW(ReqTag=dev.next_tag(), ExpectedDataSize=r)/SCSICmd(OperationCode=opcode)/Raw(os.urandom(r%20))
            #cmd.show2()
            print dev.hex_dump(str(cmd))

            # do the test
            try:
                dev.send(cmd)
                reply = dev.read_reply()
            except USBException as e:
                print "Exception: %s while processing command %u" % (e, dev.cur_tag())
                dev.reset()

            # display any data in reply
            if Raw in reply and len(reply)>0:
                print dev.hex_dump(str(reply[Raw]))

            # check CSW
            ok = dev.check_status(reply)
            if len(reply) == 0:
                print "No response to command %u!" % dev.cur_tag()

            # monitor target
            if test%10==0:
                 if not dev.is_alive():
                    print "Device not responding, resetting!"
                    dev.reset()

    except USBException as e:
        print "Exception: %s in command loop, resetting!" % e
        dev.reset()

