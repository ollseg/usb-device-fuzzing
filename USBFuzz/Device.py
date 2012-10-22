#!/usr/bin/env python

import usb.core
import usb.util
import usb.control
import sys
import time

from USBFuzz.Exceptions import *


class USBDevice:
    '''
    A simple USB Device base class.
    '''


    def __init__(self, vid, pid, timeout = 500):
        '''
        @type    vid: string
        @param    vid: Vendor ID of device in hex
        @type    pid: string
        @param    pid: Product ID of device in hex
        @type    timeout: number
        @param    timeout: number of msecs to wait for reply
        '''
        
        self._vid = int(vid,16)
        self._pid = int(pid,16)
        self._timeout = int(timeout)
        if self._timeout < 100:
            self._timeout = 100

        self._device = usb.core.find(idVendor=self._vid, idProduct=self._pid)
        if self._device == None:
            raise USBException("Error opening device 0x%x:0x%x!" % (self._vid, self._pid))

        try:
            self._device.set_configuration()
        except usb.core.USBError as e:
            if e.errno == 16: # Ignore "Resource Busy" error
                pass
            else:
                raise e


    FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
    def hex_dump(self, src, length=32):
        N=0
        result=''
        while src:
           s,src = src[:length],src[length:]
           hexa = ' '.join(["%02X"%ord(x) for x in s])
           s = s.translate(self.FILTER)
           result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
           N+=length
        return result


    def reset(self):

        try:
            self._device.reset()
        except usb.core.USBError as e:
            raise USBException('Device could not be reset!')

        try:
            res = usb.control.get_status(self._device)
        except usb.core.USBError as e:
            raise USBException('Device not responding after reset!')



    def clear_stall(self, ep):

        try:
            usb.control.clear_feature(self._device, usb.control.ENDPOINT_HALT, ep)
        except usb.core.USBError as e:
            raise USBStalled('Could\'nt clear stall on ep 0x%0.2x!' % ep.bEndpointAddress)


    def is_alive(self):

        try:
            res = usb.control.get_status(self._device)
        except usb.core.USBError as e:
            if e.backend_error_code == -7: # LIBUSB_ERROR_TIMEOUT
                raise USBException('Device not responding!')
                                
            elif (e.backend_error_code == -4): # LIBUSB_ERROR_NO_DEVICE
                raise USBException('Device disconnected!')

            elif (e.backend_error_code == -3): # LIBUSB_ERROR_ACCESS
                raise USBException('Device couldn\'t be accessed!')

            else:
                raise e
        
        if res < 0 or res > 2:
            return False

        return True




class BulkPipe(USBDevice):
    '''
    A simple interface to a USB Device bulk transfer pipe.
    '''

    def __init__(self, vid, pid, iface = 0, timeout = 500):
        '''
        @type    vid: string
        @param    vid: Vendor ID of device in hex
        @type    pid: string
        @param    pid: Product ID of device in hex
        @type    iface: number
        @param    iface: Device Interface to use
        @type    timeout: number
        @param    timeout: number of msecs to wait for reply
        '''

        USBDevice.__init__(self, vid, pid, timeout)
        self._iface = int(iface)
        
        self._epin = None
        self._epout = None
    
        # find bulk endpoints
        for c in self._device:
            for i in c:
                #print("Interface: 0x%x 0x%x/0x%x/0x%x " % (i.bInterfaceNumber, i.bInterfaceClass, i.bInterfaceSubClass, i.bInterfaceProtocol))
                if i.bInterfaceNumber == self._iface:
                    for ep in i:
                        #print("Endpoint: 0x%x 0x%x " % (ep.bEndpointAddress, ep.bmAttributes))
                        if ep.bmAttributes == usb.ENDPOINT_TYPE_BULK:
                            if ep.bEndpointAddress & usb.ENDPOINT_DIR_MASK == usb.ENDPOINT_IN:
                                self._epin = ep
                            else:
                                self._epout = ep

        if not self._epin or not self._epout:
            raise USBException("Couldn't find bulk endpoints! (try different interface?)")
        #print("Using endpoints: 0x%x 0x%x " % (self._epin.bEndpointAddress, self._epout.bEndpointAddress))

        # claim interface from kernel
        try:
            self._device.detach_kernel_driver(self._iface)
        except usb.core.USBError as e:
            if e.errno == 2: # "Entity not found"
                pass
            else:
                raise e



    def send(self, data):
        '''
        Send data on pipe
        
        @type    data: string
        @param    data: Data to send
        '''

        retry = 2
        while retry > 0:
            try:
                self._epout.write(str(data), timeout=self._timeout)
                retry = 0
                #print("Data OUT, %u bytes: " % (len(data)))
                #print '>>>>>>>>>>>>>>>>>>>>>>>>>>'
                #print self.hex_dump(data)
            except usb.core.USBError as e:
                #print("Data OUT error: %i" % e.backend_error_code)
                retry -= 1
                if e.backend_error_code == -9: # LIBUSB_ERROR_PIPE
                    if retry == 0:
                        if usb.control.get_status(self._device, self._epout) & 1 == 1:
                            raise USBStalled("EP 0x%0.2x stalled" % self._epout.bEndpointAddress)
                        raise USBException("USB Pipe Error when writing on EP 0x%0.2x" % self._epout.bEndpointAddress)
                    self.clear_stall(self._epout)
                    time.sleep(0.001)

                elif e.backend_error_code == -7:
                    raise USBTimeout("USB timeout when writing on EP 0x%0.2x" % self._epout.bEndpointAddress)
                else:
                    raise e
    

    def receive(self, size = None):

        if size is None:
            size = 0x1000
            
        retry = 5
        while retry > 0:
            try:
                data = self._epin.read(size, timeout=self._timeout)
                retry = 0
            except usb.core.USBError as e:
                #print("Data IN error: %i" % e.backend_error_code)
                retry -= 1
                if e.backend_error_code == -9: # LIBUSB_ERROR_PIPE
                    if retry == 0:
                        if usb.control.get_status(self._device, self._epin) & 1 == 1:
                            raise USBStalled("EP 0x%0.2x stalled" % self._epin.bEndpointAddress)
                        raise USBException("USB Pipe Error when reading on EP 0x%0.2x" % self._epin.bEndpointAddress)
                    self.clear_stall(self._epin)
                    time.sleep(0.001)

                elif e.backend_error_code == -7:
                    #raise USBTimeout("USB timeout when reading on EP 0x%0.2x" % self._epin.bEndpointAddress)
                    return ""
                else:
                    raise e

        if len(data) == 0:
            raise USBException("receive() returned no data!")
        string = ''.join(chr(byte) for byte in data)
        #print("Data IN, %u bytes: " % (len(data)))
        #print '<<<<<<<<<<<<<<<<<<<<<<<<<<'
        #print self.hex_dump(string)

        return string
        

