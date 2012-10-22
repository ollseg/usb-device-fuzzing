#!/usr/bin/env python

from scapy.packet import Raw, fuzz

from USBFuzz.CCID import *

import sys

arg = sys.argv[1].split(':')
dev = CCIDDevice(vid=arg[0], pid=arg[1], timeout=2000)
dev.reset()

while dev.is_alive():

    print "Sending command %u" % (dev.cur_seq() + 1)

    cmd = CCID(bSeq=dev.next_seq(),bSlot=0)/PC_to_RDR_XfrBlock()/fuzz(APDU(CLA=0x80))

    dev.send(str(cmd))
    res = dev.receive()

    if (len(res)):
        reply = CCID(res)
        if Raw in reply and reply[Raw].load[0] != '\x6D':
            cmd.show2()
            print dev.hex_dump(str(cmd))
            reply.show2()
            if Raw in reply:
                print dev.hex_dump(str(reply[Raw]))
    else:
        print "No response to command %u!" % dev.cur_seq()
        cmd.show2()


