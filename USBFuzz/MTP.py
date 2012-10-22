#!/usr/bin/env python

from USBFuzz.Exceptions import *
from USBFuzz.Device import BulkPipe

from scapy.fields import *
from scapy.packet import Packet, Raw, bind_layers

import os
import struct


OpCodes = {
    "GetDeviceInfo":        0x1001,
    "OpenSession":          0x1002,
    "CloseSession":         0x1003,
    "GetStorageIDs":        0x1004,
    "GetStorageInfo":       0x1005,
    "GetNumObjects":        0x1006,
    "GetObjectHandles":     0x1007,
    "GetObjectInfo":        0x1008,
    "GetObject":            0x1009,
    "GetThumb":             0x100a,
    "DeleteObject":         0x100b,
    "SendObjectInfo":       0x100c,
    "SendObject":           0x100d,
    "InitiateCapture":      0x100e,
    "FormatStore":          0x100f,
    "ResetDevice":          0x1010,
    "SelfTest":             0x1011,
    "SetObjectProtection":  0x1012,
    "PowerDown":            0x1013,
    "GetDevicePropDesc":    0x1014,
    "GetDevicePropValue":   0x1015,
    "SetDevicePropValue":   0x1016,
    "ResetDevicePropValue": 0x1017,
    "TerminateOpenCapture": 0x1018,
    "MoveObject":           0x1019,
    "CopyObject":           0x101a,
    "GetPartialObject":     0x101b,
    "InitiateOpenCapture":  0x101c,
    "GetObjectPropsSupported":0x9801,
    "GetObjectPropDesc":      0x9802,
    "GetObjectPropValue":     0x9803,
    "SetObjectPropValue":     0x9804,
    "GetObjectReferences":    0x9810,
    "SetObjectReferences":    0x9811,
    "Skip": 0x9820
}

ResCodes = {
    "Undefined": 0x2000,
    "OK": 0x2001,
    "General_Error":     0x2002,
    "Session_Not_Open":    0x2003,
    "Invalid_TransactionID":    0x2004,
    "Operation_Not_Supported":    0x2005,
    "Parameter_Not_Supported":    0x2006,
    "Incomplete_Transfer":    0x2007,
    "Invalid_StorageID":    0x2008,
    "Invalid_ObjectHandle":    0x2008,
    "DeviceProp_Not_Supported":    0x200a,
    "Invalid_ObjectFormatCode":    0x200b,
    "Store_Full":    0x200c,
    "Object_WriteProtected":    0x200d,
    "Store_Read-Only":    0x200e,
    "Access_Denied":    0x200e,
    "No_Thumbnail_Present":     0x2010,
    "SelfTest_Failed":    0x2011,
    "Partial_Deletion":    0x2012,
    "Store_Not_Available":0x2013,
    "Specification_By_Format_Unsupported":0x2014,
    "No_Valid_ObjectInfo":    0x2015,
    "Invalid_Code_Format":    0x2016,
    "Unknown_Vendor_Code":    0x2017,
    "Capture_Already_Terminated":    0x2018,
    "Device_Busy":    0x2019,
    "Invalid_ParentObject":    0x201a,
    "Invalid_DeviceProp_Format":    0x201b,
    "Invalid_DeviceProp_Value":    0x201c,
    "Invalid_Parameter":    0x201d,
    "Session_Already_Open":    0x201e,
    "Transaction_Cancelled":    0x201f,
    "Specification_of_Destination_Unsupported":    0x2020,
    "Invalid_ObjectPropCode":    0xa801,
    "Invalid_ObjectProp_Format":    0xa802,
    "Invalid_ObjectProp_Value":    0xa803,
    "Invalid_ObjectReference":    0xa804,
    "Group_Not_Supported":    0xa805,
    "Invalid_Dataset":    0xa806,
    "Specification_By_Group_Unsupported":    0xa807,
    "Specification_By_Depth_Unsupported":    0xa808,
    "Object_Too_Large":    0xa809,
    "ObjectProp_Not_Supported":     0xa80a
}


class Container(Packet):
    name = "PTP/MTP Container "

    _Types = {"Undefined":0, "Operation":1, "Data":2, "Response":3, "Event":4}

    _Codes = {}
    _Codes.update(OpCodes)
    _Codes.update(ResCodes)
    fields_desc = [ LEIntField("Length", None),
                    LEShortEnumField("Type", 1, _Types),
                    LEShortEnumField("Code", None, _Codes),
                    LEIntField("TransactionID", None) ]

    def post_build(self, p, pay):
        # update Code field
        if self.Code is None:
            self.Code = struct.unpack("<H", pay[:2])[0]
            p = p[:-6] + struct.pack("<H", self.Code) + p[-4:]
        # update TransactionID field
        if self.TransactionID is None:
            self.TransactionID = struct.unpack("<I", pay[6:10])[0]
            p = p[:-4] + struct.pack("<I", self.TransactionID)
        # default Container Length
        if self.Length is None:
            self.Length = len(pay)+1
            p = struct.pack("<I", len(pay)+1) + p[4:]
        return p+pay


class Operation(Packet):
    name = "Operation "
    fields_desc = [ LEShortEnumField("OpCode", 0, OpCodes), 
                    LEIntField("SessionID", 0),
                    LEIntField("TransactionID", 1),
                    LEIntField("Parameter1", 0),
                    LEIntField("Parameter2", 0),
                    LEIntField("Parameter3", 0),
                    LEIntField("Parameter4", 0),
                    LEIntField("Parameter5", 0) ]
'''
                    ConditionalField(LEIntField("Parameter2", 0), lambda pkt:pkt.fields.has_key("Parameter2")),
                    ConditionalField(LEIntField("Parameter3", 0), lambda pkt:pkt.fields.has_key("Parameter3")),
                    ConditionalField(LEIntField("Parameter4", 0), lambda pkt:pkt.fields.has_key("Parameter4")),
                    ConditionalField(LEIntField("Parameter5", 0), lambda pkt:pkt.fields.has_key("Parameter5")) ]
'''
class Response(Packet):
    name = "Response "
    fields_desc = [ LEShortEnumField("ResCode", 0, ResCodes),
                    LEIntField("SessionID", 0),
                    LEIntField("TransactionID", 1),
                    LEIntField("Parameter1", 0),
                    LEIntField("Parameter2", 0),
                    LEIntField("Parameter3", 0),
                    LEIntField("Parameter4", 0),
                    LEIntField("Parameter5", 0) ]


bind_layers(Container, Operation, {"Type": 1})
bind_layers(Container, Response, {"Type": 3})






class MTPDevice(BulkPipe):

    def __init__(self, vid, pid, iface = 0, wait = 1, timeout = 500):

        '''
        @type    vid: string
        @param    vid: Vendor ID of device in hex
        @type    pid: string
        @param    pid: Product ID of device in hex
        @type    iface: number
        @param    iface: Device Interface to use
        @type    timeout: wait
        @param    timeout: number of usecs to wait before asking for reply
        @type    timeout: number
        @param    timeout: number of usecs to wait for reply to arrive
        '''

        BulkPipe.__init__(self, vid, pid, iface, timeout)
        
        self._wait = int(wait)
        self._session = 0



    def current_session(self):
    
        return self._session


    def new_session(self):
    
        self._session = struct.unpack("I", os.urandom(4))[0]
        return self._session



    def read_response(self, transaction=1):

        retry = 1
        response = []
        while 1:
            try:
                data = self.receive()
                #print "read %u bytes: %s" % (len(data), self.hex_dump(data))
            except USBException as e:
                print "%s in read_response(), resetting!" % e
                self.reset()
                return response

            if len(data) == 0:
                # retry reading
                if retry > 0:
                    # wait for device to process before asking again
                    time.sleep(0.001 * self._wait)
                    retry -= 1
                    continue
                return response

            if len(data) < 12:
                print "Incomplete Container in read_response()!"
                response.append(Raw(data))
                return response

            c = Container(data)

            if c.TransactionID != transaction:
                continue

            # add Container to the response packets
            response.append(c)

            if c.Type == Container._Types["Response"]:
                return response

            if c.Type == Container._Types["Data"]:
                if Raw not in c or len(c) != c.Length:
                    print "Invalid length (%u!=%u) in read_response()!" % (len(c), c.Length)



    def is_alive(self):

        if not BulkPipe.is_alive(self):
            return False

        try:
            self.send(Container()/Operation(OpCode=OpCodes["Skip"], TransactionID=0xdeadbeef))
            response = self.read_response(0xdeadbeef)
        except USBException as e:
            print "%s in MTP.is_alive()!" % e
            return False

        if len(response) == 0:
            print "Device not responding in MTP.is_alive()!"
            return False

        return True


