#!/usr/bin/env python

from USBFuzz.Device import BulkPipe

from scapy.fields import *
from scapy.packet import Packet, Raw, bind_layers

'''
This builds on qcombbdbg by Guillaume Delugre (guillaume@security-labs.org)
Big thanks to him for his good work reversing Qualcomm baseband software!
'''

CRC16_CCITT_TABLE = [
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
    ]

def crc16(data):
    crc = 0xffff
    for byte in data:
        crc = (crc >> 8) ^ CRC16_CCITT_TABLE[(crc ^ ord(byte)) & 0xff]
    return crc ^ 0xffff


CommandCodes = {
    "Version info"  : 0,
    "ESN"           : 1,  # ESN 
    "PEEKB        ": 2,  # Peek byte 
    "PEEKW        ": 3,  # Peek word 
    "PEEKD        ": 4,  # Peek dword 
    "POKEB        ": 5,  # Poke byte 
    "POKEW        ": 6,  # Poke word 
    "POKED        ": 7,  # Poke dword 
    "OUTP         ": 8,  # Byte output 
    "OUTPW        ": 9,  # Word output 
    "INP          ": 10, # Byte input 
    "INPW         ": 11, # Word input 
    "STATUS       ": 12, # Station status 
    "LOGMASK      ": 15, # Set logging mask 
    "LOG          ": 16, # Log packet 
    "NV_PEEK      ": 17, # Peek NV memory 
    "NV_POKE      ": 18, # Poke NV memory 
    "BAD_CMD      ": 19, # Invalid command (response) 
    "BAD_PARM     ": 20, # Invalid parameter (response) 
    "BAD_LEN      ": 21, # Invalid packet length (response) 
    "BAD_DEV      ": 22, # Not accepted by the device (response) 
    "BAD_MODE     ": 24, # Not allowed in this mode (response) 
    "TAGRAPH      ": 25, # Info for TA power and voice graphs 
    "MARKOV       ": 26, # Markov stats 
    "MARKOV_RESET ": 27, # Reset Markov stats 
    "DIAG_VER     ": 28, # Diagnostic Monitor version 
    "TIMESTAMP    ": 29, # Return a timestamp 
    "TA_PARM      ": 30, # Set TA parameters 
    "MESSAGE      ": 31, # Request for msg report 
    "HS_KEY       ": 32, # Handset emulation -- keypress 
    "HS_LOCK      ": 33, # Handset emulation -- lock or unlock 
    "HS_SCREEN    ": 34, # Handset emulation -- display request 
    "PARM_SET     ": 36, # Parameter download 
    "NV_READ      ": 38, # Read NV item 
    "NV_WRITE     ": 39, # Write NV item 
    "CONTROL      ": 41, # Mode change request 
    "ERR_READ     ": 42, # Error record retreival 
    "ERR_CLEAR    ": 43, # Error record clear 
    "SER_RESET    ": 44, # Symbol error rate counter reset 
    "SER_REPORT   ": 45, # Symbol error rate counter report 
    "TEST         ": 46, # Run a specified test 
    "GET_DIPSW    ": 47, # Retreive the current DIP switch setting 
    "SET_DIPSW    ": 48, # Write new DIP switch setting 
    "VOC_PCM_LB   ": 49, # Start/Stop Vocoder PCM loopback 
    "VOC_PKT_LB   ": 50, # Start/Stop Vocoder PKT loopback 
    "ORIG         ": 53, # Originate a call 
    "END          ": 54, # End a call 
    "SW_VERSION   ": 56, # Get software version 
    "DLOAD        ": 58, # Switch to downloader 
    "TMOB         ": 59, # Test Mode Commands and FTM commands
    "STATE        ": 63, # Current state of the phone 
    "PILOT_SETS   ": 64, # Return all current sets of pilots 
    "SPC          ": 65, # Send the Service Programming Code to unlock 
    "BAD_SPC_MODE ": 66, # Invalid NV read/write because SP is locked 
    "PARM_GET2    ": 67, # (obsolete) 
    "SERIAL_CHG   ": 68, # Serial mode change 
    "PASSWORD     ": 70, # Send password to unlock secure operations 
    "BAD_SEC_MODE ": 71, # Operation not allowed in this security state 
    "PRL_WRITE         ": 72,  # Write PRL 
    "PRL_READ          ": 73,  # Read PRL 
    "SUBSYS            ": 75,  # Subsystem commands 
    "FEATURE_QUERY     ": 81,
    "SMS_READ          ": 83,  # Read SMS message out of NV memory 
    "SMS_WRITE         ": 84,  # Write SMS message into NV memory 
    "SUP_FER           ": 85,  # Frame Error Rate info on multiple channels 
    "SUP_WALSH_CODES   ": 86,  # Supplemental channel walsh codes 
    "SET_MAX_SUP_CH    ": 87,  # Sets the maximum # supplemental channels 
    "PARM_GET_IS95B    ": 88,  # Get parameters including SUPP and MUX2 
    "FS_OP             ": 89,  # Embedded File System (EFS) operations 
    "AKEY_VERIFY       ": 90,  # AKEY Verification 
    "HS_BMP_SCREEN     ": 91,  # Handset Emulation -- Bitmap screen 
    "CONFIG_COMM       ": 92,  # Configure communications 
    "EXT_LOGMASK       ": 93,  # Extended logmask for > 32 bits 
    "EVENT_REPORT      ": 96,  # Static Event reporting 
    "STREAMING_CONFIG  ": 97,  # Load balancing etc 
    "PARM_RETRIEVE     ": 98,  # Parameter retrieval 
    "STATUS_SNAPSHOT   ": 99,  # Status snapshot 
    "RPC               ": 100, # Used for RPC 
    "GET_PROPERTY      ": 101,
    "PUT_PROPERTY      ": 102,
    "GET_GUID          ": 103, # GUID requests 
    "USER_CMD          ": 104, # User callbacks 
    "GET_PERM_PROPERTY ": 105,
    "PUT_PERM_PROPERTY ": 106,
    "PERM_USER_CMD     ": 107, # Permanent user callbacks 
    "GPS_SESS_CTRL     ": 108, # GPS session control 
    "GPS_GRID          ": 109, # GPS search grid 
    "GPS_STATISTICS    ": 110,
    "TUNNEL            ": 111, # Tunneling command code 
    "RAM_RW            ": 112, # Calibration RAM control using DM 
    "CPU_RW            ": 113, # Calibration CPU control using DM 
    "SET_FTM_TEST_MODE ": 114, # Field (or Factory?) Test Mode 
    "LOG_CONFIG        ": 115, # New logging config command 
    "EXT_BUILD_ID      ": 124,
    "EXT_MESSAGE_CONFIG": 125,
    "EVENT_GET_MASK    ": 129,
    "EVENT_SET_MASK    ": 130
}

ResponseCodes = {
    "Success": 0,
    "Invalid arguments": 1,
    "Serial config failed": 2,
    "Values not found": 3,
    "Unexpected command": 4,
    "Invalid command length": 5,
    "Malformed command": 6,
    "Invalid command": 7,
    "Invalid parameter": 8,
    "Command not accepted": 9,
    "Invalid mode": 10,
    "NV Command failed": 11,
    "SPC is locked": 12,
    "NV busy error": 13,
    "Invalid NV command": 14,
    "NV memory full error": 15,
    "NV Command error": 16,
    "NV error inactive": 17,
    "Invalid parameter in NV command": 18,
    "NV error read-only": 19,
    "Command failed": 20
}


class QCDMFrame(Packet):
    name = "Qualcomm DIAG "
    fields_desc = [ LEShortField("crc", None),
                    XByteField("eof", 0x7E) ]
                    
    def post_build(self, p, pay):
        # calculate crc
        if self.crc is None:
            self.crc = crc16(pay)

        # build packet
        ep = pay + struct.pack("<H", self.crc)

        # HDLC-type framing
        ep = ep.replace("\x7d", "\x7d\x5d")
        ep = ep.replace("\x7e", "\x7d\x5e")
        ep += struct.pack("B", self.eof)
        return ep

    def pre_dissect(self, s):
        # HDLC-type framing
        s = s.replace("\x7d\x5d", "\x7d")
        s = s.replace("\x7d\x5e", "\x7e")
        # reorder the packet bytes to put contents as "payload"
        return s[-3:] + s[:-3]


class Command(Packet):
    name = "Command "
    fields_desc = [ ByteEnumField("code", 0, CommandCodes) ]

bind_layers(QCDMFrame, Command)


class QCDMDevice(BulkPipe):

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
        

    def receive_response(self):

        data = self.receive()
        while len(data) > 0 and data[-1] != "\x7e":
            d = self.receive()
            if len(d) == 0:
                break
            data += d

        if len(data) < 4 or data[-1] != "\x7e":
            return Raw(data)

        return QCDMFrame(data)


    def is_alive(self):
    
        if not BulkPipe.is_alive(self):
            return False

        self.send(QCDMFrame()/Command(code=0))
        res = self.receive_response()

        if QCDMFrame not in res:
            print "Device not responding to DIAG commands!"
            print self.hex_dump(str(res))
            return False

        if ord(str(res.payload)[0]) == 0:
            return True

        print "Device responed in an unexpected way!" 
        print self.hex_dump(str(res.payload))

        return False


