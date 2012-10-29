usb-device-fuzzing
==================

Some tools for testing USB devices

This code was first released at T2 Infosec 2012: http://www.t2.fi/2012/

simple_ctrl_fuzzer.py: simple fuzzer for USB control transfers

USBFuzz: python modules for building USB fuzzers

USBFuzz.Exceptions: common exception definitions for the USBFuzz modules

USBFuzz.Device: module to interface with USB devices

USBFuzz.MSC: scapy layers and USB device interface class for the USB Bulk-Only Mass Storage Class

USBFuzz.SCSI: scapy layers for SCSI primary and bulk commands, used by USBFuzz.MSC

USBFuzz.CCID: scapy layers and USB device interface class for the USB Integrated Circuit Cards Interface Device Class

USBFuzz.MTP: scapy layers and USB device interface class for the USB Media Tranfer Protocol (based on Picture Transfer Protocol)

USBFuzz.QCDM: scapy layers and USB device interface class for the Qualcomm baseband DIAG protocol

examples: examples of simple fuzzers built using the USBFuzz modules

