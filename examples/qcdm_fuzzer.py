#!/usr/bin/env python

from scapy.packet import Raw, fuzz

from USBFuzz.QCDM import *

import os
import sys

arg = sys.argv[1].split(':')
iface = 0
if len(sys.argv) > 2:
    iface = int(sys.argv[2])
dev = QCDMDevice(vid=arg[0], pid=arg[1], iface=iface)


while dev.is_alive():

    cmd = QCDMFrame()/fuzz(Command())/Raw(os.urandom(8))

    # avoid switching to downloader or test modes
    if cmd.code == 58 or cmd.code == 59:
        cmd.code = 0

    cmd.show2()
    print dev.hex_dump(str(cmd[Raw]))
    dev.send(str(cmd))
    res = dev.receive_response()

    if QCDMFrame in res:
        res.show()
        if Raw in res:
            print dev.hex_dump(str(res[Raw]))
    else:
        print "No response to command!"
        print dev.hex_dump(str(res))



