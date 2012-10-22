#!/usr/bin/env python

class USBException(Exception):
    def __init__(self, strerror):
        Exception.__init__(self, strerror)

class USBStalled(USBException):
    def __init__(self, strerror):
        USBException.__init__(self, strerror)

class USBTimeout(USBException):
    def __init__(self, strerror):
        USBException.__init__(self, strerror)


