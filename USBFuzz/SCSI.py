#!/usr/bin/env python

from scapy.fields import *
from scapy.packet import Packet, Raw, bind_layers


class SCSICmd(Packet):
    name = "SCSI Command "
    fields_desc = [ XByteField("OperationCode", 0) ]


class RequestSense(Packet):
    name = "RequestSense "
    fields_desc = [ ByteEnumField("Format", 0, {0:"Fixed", 1:"Descriptor"}),
                    XByteField("Reserved2", 0),
                    XByteField("Reserved3", 0),
                    XByteField("AllocationLength", 252),
                    XByteField("Control", 0) ]


class FormatUnit(Packet):
    name = "FormatUnit "
    fields_desc = [ XByteField("LUN-etc", 0x17), # TODO: How does scapy deal with <8bit integers?
                    XByteField("VendorSpec", 0),
                    ShortField("Interleave", 0),
                    XByteField("Reserved1", 0)]


class Read6(Packet):
    name = "Read(6) "
    fields_desc = [ XByteField("LogicalBlockAddrHigh", 0),
                    XShortField("LogicalBlockAddr", 0),
                    ByteField("TransferLength", 1), # Number of blocks
                    XByteField("Control", 0) ]


class Inquiry(Packet):
    name = "Inquiry(6) "
    fields_desc = [ XByteField("Reserved1", 1),
                    XByteField("PageCode", 1),
                    ShortField("AllocationLength", 36),
                    XByteField("Control", 1) ]


class ReadCapacity10(Packet):
    name = "ReadCapacity(10) "
    fields_desc = [ XByteField("Reserved1", 0),
                    XIntField("LogicalBlockAddr", 0),
                    XByteField("Reserved2", 0),
                    XByteField("Reserved3", 0),
                    XByteField("Reserved4", 0),
                    XByteField("Control", 0) ]


class Read10(Packet):
    name = "Read(10) "
    fields_desc = [ XByteField("Reserved1", 0),
                    XIntField("LogicalBlockAddr", 0),
                    XByteField("Reserved2", 0),
                    ShortField("TransferLength", 1), # Number of blocks
                    XByteField("Control", 0) ]


class ReadTOC(Packet):
    name = "ReadTOC "
    fields_desc = [ ByteEnumField("MSF", 0, {0:"", 2:""}),
                    XByteField("Format-A", 0),
                    XByteField("Reserved1", 0),
                    XByteField("Reserved2", 0),
                    XByteField("Reserved3", 0),
                    XByteField("Reserved4", 0),
                    ShortField("AllocationLength", 12),
                    XByteField("Format-B", 0x40)]


bind_layers(SCSICmd, RequestSense, {"OperationCode":0x03})
bind_layers(SCSICmd, FormatUnit, {"OperationCode":0x04})
bind_layers(SCSICmd, Read6, {"OperationCode":0x0A})
bind_layers(SCSICmd, Inquiry, {"OperationCode":0x12})
bind_layers(SCSICmd, ReadCapacity10, {"OperationCode":0x25})
bind_layers(SCSICmd, Read10, {"OperationCode":0x28})
bind_layers(SCSICmd, ReadTOC, {"OperationCode":0x43})

