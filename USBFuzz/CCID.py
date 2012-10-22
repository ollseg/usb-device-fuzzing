#!/usr/bin/env python

from USBFuzz.Device import BulkPipe

from scapy.fields import *
from scapy.packet import Packet, bind_layers

class CCID(Packet):
    name = "CCID "
    fields_desc = [ XByteField("bMessageType", 0),
                    LEIntField("dwLength", None),
                    XByteField("bSlot", 0),
                    XByteField("bSeq", 0) ]
                    
    def post_build(self, p, pay):
        if len(pay) < 3: # make sure payload is at least 3 bytes
            pay += '\x00' * (3-len(pay))
        if self.dwLength is None:
            p = p[:1] + struct.pack("<I", len(pay) - 3) + p[5:]
        return p+pay


class PC_to_RDR_SetParameters(Packet):
    name = "PC_to_RDR_SetParameters "
    fields_desc = [ ByteEnumField("bProtocolNum", 0, {0:"T0", 1:"T1", 0x80:"2-wire", 0x81:"3-wire", 0x82:"I2C"}),
                    XShortField("abRFU", 0) ]
bind_layers(CCID, PC_to_RDR_SetParameters, bMessageType=0x61 )


class PC_to_RDR_IccPowerOn(Packet): # 62
    name = "PC_to_RDR_IccPowerOn "
    fields_desc = [ ByteField("bPowerSelect", 0),
                    XShortField("abRFU", 0) ]
bind_layers(CCID, PC_to_RDR_IccPowerOn, bMessageType=0x62 )


class PC_to_RDR_IccPowerOff(Packet):
    name = "PC_to_RDR_IccPowerOff "
    fields_desc = [ X3BytesField("abRFU", 0) ]
bind_layers(CCID, PC_to_RDR_IccPowerOff, bMessageType=0x63 )


class PC_to_RDR_GetSlotStatus(Packet):
    name = "PC_to_RDR_GetSlotStatus "
    fields_desc = [ X3BytesField("abRFU", 0) ]
bind_layers(CCID, PC_to_RDR_GetSlotStatus, bMessageType=0x65 )


class PC_to_RDR_Secure(Packet):
    name = "PC_to_RDR_Secure "
    fields_desc = [ ByteField("bBWI", 0),
                    XShortField("wLevelParameter", 0) ]
bind_layers(CCID, PC_to_RDR_Secure, bMessageType=0x69 )


class PC_to_RDR_T0APDU(Packet):
    name = "PC_to_RDR_T0APDU "
    fields_desc = [ FlagsField("bmChanges", 0, 8, ["ClassGetResp", "ClassEnvelope"]),
                    XByteField("bClassGetResp", 0),
                    XByteField("bClassEnvelope", 0) ]
bind_layers(CCID, PC_to_RDR_T0APDU, bMessageType=0x6A )


class PC_to_RDR_Escape(Packet):
    name = "PC_to_RDR_Escape "
    fields_desc = [ X3BytesField("abRFU", 0) ]
bind_layers(CCID, PC_to_RDR_Escape, bMessageType=0x6B )


class PC_to_RDR_GetParameters(Packet):
    name = "PC_to_RDR_GetParameters "
    fields_desc = [ X3BytesField("abRFU", 0) ]
bind_layers(CCID, PC_to_RDR_GetParameters, bMessageType=0x6C )

class PC_to_RDR_ResetParameters(Packet):
    name = "PC_to_RDR_ResetParameters "
    fields_desc = [ ByteField("bMessageType", 0),
                    XShortField("abRFU", 0) ]
bind_layers(CCID, PC_to_RDR_ResetParameters, bMessageType=0x6D )       


class PC_to_RDR_IccClock(Packet):
    name = "PC_to_RDR_IccClock "
    fields_desc = [ BitEnumField("bClockCommand", 0, 8, {0:"Restart Clock", 1:"Stop Clock"}),
                    XShortField("abRFU", 0) ]
bind_layers(CCID, PC_to_RDR_IccClock, bMessageType=0x6E )


class PC_to_RDR_XfrBlock(Packet):
    name = "PC_to_RDR_XfrBlock "
    fields_desc = [ ByteField("bBWI", 0),
                    XShortField("wLevelParameter", 0) ]
bind_layers(CCID, PC_to_RDR_XfrBlock, bMessageType=0x6F )


class PC_to_RDR_Mechanical(Packet):
    name = "PC_to_RDR_Mechanical "
    fields_desc = [ ByteEnumField("bFunction", 0, {1:"Accept", 2:"Eject", 3:"Capture", 4:"Lock", 5:"Unlock"}),
                    XShortField("abRFU", 0) ]
bind_layers(CCID, PC_to_RDR_Mechanical, bMessageType=0x71 )


class PC_to_RDR_Abort(Packet):
    name = "PC_to_RDR_Abort "
    fields_desc = [ X3BytesField("abRFU", 0) ]
bind_layers(CCID, PC_to_RDR_Abort, bMessageType=0x72 )


class PC_to_RDR_SetDataRateAndClockFrequency(Packet):
    name = "PC_to_RDR_SetDataRateAndClockFrequency "
    fields_desc = [ X3BytesField("abRFU", 0),
                    LEIntField("dwClockFrequency", 0),
                    LEIntField("dwDataRate", 0) ]
bind_layers(CCID, PC_to_RDR_SetDataRateAndClockFrequency, bMessageType=0x73 )


class RDR_to_PC_DataBlock(Packet):
    name = "RDR_to_PC_DataBlock "
    fields_desc = [ XByteField("bStatus", 0),
                    XByteField("bError", 0),
                    XByteField("bChainParameter", 0) ]
bind_layers(CCID, RDR_to_PC_DataBlock, bMessageType=0x80 )


class RDR_to_PC_SlotStatus(Packet):
    name = "RDR_to_PC_SlotStatus "
    fields_desc = [ XByteField("bStatus", 0),
                    XByteField("bError", 0),
                    ByteEnumField("bClockStatus", 0, {0:"Running", 1:"Stopped Low", 2:"Stopped High", 3:"Stopped"}) ]
bind_layers(CCID, RDR_to_PC_SlotStatus, bMessageType=0x81 )


class RDR_to_PC_Parameters(Packet):
    name = "RDR_to_PC_Parameters "
    fields_desc = [ XByteField("bStatus", 0),
                    XByteField("bError", 0),
                    ByteEnumField("bProtocolNum", 0, {0:"T0", 1:"T1", 0x80:"2-wire", 0x81:"3-wire", 0x82:"I2C"}) ]
bind_layers(CCID, RDR_to_PC_Parameters, bMessageType=0x82 )


class RDR_to_PC_Escape(Packet):
    name = "RDR_to_PC_Escape "
    fields_desc = [ XByteField("bStatus", 0),
                    XByteField("bError", 0),
                    XByteField("bRFU", 0),
                    LEIntField("dwClockFrequency", 0),
                    LEIntField("dwDataRate", 0) ]
bind_layers(CCID, RDR_to_PC_Escape, bMessageType=0x83 )


class RDR_to_PC_DataRateAndClockFrequency(Packet):
    name = "RDR_to_PC_DataRateAndClockFrequency "
    fields_desc = [ XByteField("bStatus", 0),
                    XByteField("bError", 0),
                    XByteField("bRFU", 0) ]
bind_layers(CCID, RDR_to_PC_DataRateAndClockFrequency, bMessageType=0x83 )


class T0DataStructure(Packet):
    name = "T0 Data "
    fields_desc = [ BitField("bmFIndex", 0, 4),
                    BitField("bmDIndex", 0, 4),
                    XByteField("bmTCCKS", 0),
                    XByteField("bGuardTime", 0),
                    XByteField("bWaitingInteger", 0),
                    ByteEnumField("bClockStop", 0,
                            {0:"No ClockStop", 1:"ClockStop on Low", 2:"ClockStop on High", 3:"ClockStop on Either"})
                  ]
bind_layers(RDR_to_PC_Parameters, T0DataStructure, bProtocolNum=0)
bind_layers(PC_to_RDR_SetParameters, T0DataStructure, bProtocolNum=0)
bind_layers(PC_to_RDR_GetParameters, T0DataStructure, dwLength=5)


class T1DataStructure(Packet):
    name = "T0 Data "
    fields_desc = [ BitField("bmFIndex", 0, 4),
                    BitField("bmDIndex", 0, 4),
                    XByteField("bmTCCKS", 0),
                    XByteField("bGuardTime", 0),
                    XByteField("bWaitingIntegers", 0),
                    ByteEnumField("bClockStop", 0,
                            {0:"No ClockStop", 1:"ClockStop on Low", 2:"ClockStop on High", 3:"ClockStop on Either"}),
                    XByteField("bIFSC", 0),
                    XByteField("bNadValue", 0)
                  ]
bind_layers(RDR_to_PC_Parameters, T1DataStructure, bProtocolNum=1)
bind_layers(PC_to_RDR_SetParameters, T1DataStructure, bProtocolNum=1)
bind_layers(PC_to_RDR_GetParameters, T1DataStructure, dwLength=7)


class APDU(Packet):
    name = "APDU "
    fields_desc = [ XByteField("CLA", 0),
                    XByteField("INS", 0x20),
                    XByteField("P1", 0),
                    XByteField("P2", 0),
                    ByteField("L", None) ]

    def post_build(self, p, pay):
        if self.L is None:
            p = p[:4] + struct.pack("b", len(pay)) + p[5:]
        return p+pay

bind_layers(PC_to_RDR_XfrBlock, APDU)



class CCIDDevice(BulkPipe):

    def __init__(self, vid, pid, iface = 0, timeout = 500):

        '''
        @type    vid: string
        @param    vid: Vendor ID of device in hex
        @type    pid: string
        @param    pid: Product ID of device in hex
        @type    iface: number
        @param    iface: Device Interface to use
        @type    timeout: number
        @param    timeout: number of usecs to wait for reply
        '''

        BulkPipe.__init__(self, vid, pid, iface, timeout)
        
        self._seq = -1


    def cur_seq(self):
    
        return self._seq


    def next_seq(self):
    
        self._seq = (self._seq + 1) % 256
        return self._seq


    def is_alive(self):
    
        if not BulkPipe.is_alive(self):
            return False

        self.send(str(CCID(bSeq=self.next_seq())/PC_to_RDR_XfrBlock()/APDU()))
        data = self.receive(100)

        if len(data) < 1:
            print "Device not responding!"
            return False

        reply = CCID(data)
        if reply.bSeq != self._seq:
            print "Sequence number mismatch %u != %u!" % (reply.bSeq, self._seq)
            return False

        if RDR_to_PC_DataBlock in reply or RDR_to_PC_SlotStatus in reply:
            return True

        print "Failed is_alive() test!"
        reply.show2()
        if Raw in reply:
            print self.hex_dump(str(reply[Raw]))

        return False


