#!/usr/bin/env python

import os
import sys
import time
import struct

from scapy.packet import fuzz
from USBFuzz.MTP import *

arg = sys.argv[1].split(':')
dev = MTPDevice(vid=arg[0], pid=arg[1], wait=500, timeout=50)
dev.reset()

# open a session
s = dev.new_session()
cmd = Container()/Operation(OpCode=OpCodes["OpenSession"], Parameter1=s)
cmd.show2()
dev.send(cmd)
response = dev.read_response()
if len(response[0]) != 12 or response[0].Code != ResCodes["OK"]:
    print "Error opening session!"
    for packet in response:
        packet.show()
    sys.exit()

while True:    

    while dev.is_alive():

        trans = struct.unpack("I", os.urandom(4))[0]
        r = struct.unpack("H", os.urandom(2))[0]
        opcode = OpCodes.items()[r%len(OpCodes)][1]
        if opcode == OpCodes["CloseSession"]:
            opcode = 0
        cmd = Container()/fuzz(Operation(OpCode=opcode, TransactionID=trans, SessionID=dev.current_session()))

        dev.send(cmd)
        response = dev.read_response(trans)

        if len(response) == 0:
            print "No response to transaction %u" % trans
        elif response[-1].Type == 3 and response[-1].Code == ResCodes["Operation_Not_Supported"]:
            print "Operation %x not supported!" % cmd.OpCode
        else:
            cmd.show2()
            for packet in response:
                if packet.Type == 2:
                    print dev.hex_dump(str(packet.payload))
                else:
                    packet.show()

    dev.reset()
