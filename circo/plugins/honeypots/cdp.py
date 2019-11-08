"""
Cisco Discovery Protocol (CDP) Honeypot
"""
import logging
import re
import threading
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.0"


class CDPHandler(threading.Thread):
    """
    Class to handle CDP packets, will start in background and send
    packets every 60 seconds, pretend to be a Cisco Phone or Switch
    """
    def __init__(self, iface, mac, src_ip, name, port, model, devicetype):
        # devicetype should be 'switch' or 'phone'
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        load_contrib('cdp')
        self.logger = logging.getLogger(__name__)
        self.iface = iface
        self.mac = mac
        self.src_ip = src_ip
        self.name = name
        self.port = port
        self.type = devicetype
        if self.type == 'switch':
            with open('plugins/honeypots/Cisco/' + model + '/show_version.txt') as sfile:
                ver = sfile.readlines()
            self.version = ver[:4]
            for line in ver:
                if 'processor' in line:
                    self.platform = re.findall(r'(.*?) \(', line)[0]
                    break
        elif self.type == 'phone':
            self.platform = 'Cisco IP Phone 7975'
            self.version = 'SIP75.8-5-3SR1S'

    def cisco_ios(self):
        """
        Build Fake Cisco Switch CDP packet
        """
        self.logger.debug('Crafting CDP Switch packet')
        fakepkt = Dot3()/LLC()/SNAP()/CDPv2_HDR()
        fakepkt[Dot3].dst = '01:00:0c:cc:cc:cc'
        fakepkt[Dot3].src = self.mac
        fakepkt[CDPv2_HDR].msg = CDPMsgDeviceID()
        fakepkt[CDPMsgDeviceID].val = self.name
        fakepkt[CDPMsgDeviceID].len = len(fakepkt[CDPMsgDeviceID])
        fakepkt = fakepkt/CDPMsgSoftwareVersion()
        fakepkt[CDPMsgSoftwareVersion].val = self.version
        fakepkt[CDPMsgSoftwareVersion].len = len(fakepkt[CDPMsgSoftwareVersion])
        fakepkt = fakepkt/CDPMsgPlatform()
        fakepkt[CDPMsgPlatform].val = self.platform
        fakepkt[CDPMsgPlatform].len = len(fakepkt[CDPMsgPlatform])
        fakepkt = fakepkt/CDPMsgAddr()
        fakepkt[CDPMsgAddr].naddr = 1
        fakepkt[CDPMsgAddr].addr = CDPAddrRecordIPv4()
        fakepkt[CDPMsgAddr][CDPAddrRecordIPv4].addr = self.src_ip
        fakepkt = fakepkt/CDPMsgPortID()
        fakepkt[CDPMsgPortID].iface = self.port
        fakepkt[CDPMsgPortID].len = len(fakepkt[CDPMsgPortID])
        fakepkt = fakepkt/CDPMsgCapabilities(cap=40)
        fakepkt = fakepkt/CDPMsgProtoHello()
        fakepkt[CDPMsgProtoHello].protocol_id = 0x112
        fakepkt[CDPMsgProtoHello].data = '\x00\x00\x00\x00\xff\xff\xff\xff\x01\x02!\xff\x00\x00\x00\x00\x00\x00X\x97\x1e\x1c/\x00\xff\x00\x00'
        fakepkt[CDPMsgProtoHello].len = len(fakepkt[CDPMsgProtoHello])
        fakepkt = fakepkt/CDPMsgVTPMgmtDomain()
        fakepkt[CDPMsgVTPMgmtDomain].len = len(fakepkt[CDPMsgVTPMgmtDomain])
        fakepkt = fakepkt/CDPMsgNativeVLAN()
        fakepkt[CDPMsgNativeVLAN].vlan = 100
        fakepkt[CDPMsgNativeVLAN].len = len(fakepkt[CDPMsgNativeVLAN])
        fakepkt = fakepkt/CDPMsgDuplex(duplex=1)
        fakepkt = fakepkt/CDPMsgTrustBitmap()
        fakepkt = fakepkt/CDPMsgUntrustedPortCoS()
        fakepkt = fakepkt/CDPMsgMgmtAddr()
        fakepkt[CDPMsgMgmtAddr].naddr = 1
        fakepkt[CDPMsgMgmtAddr].addr = CDPAddrRecordIPv4()
        fakepkt[CDPMsgMgmtAddr][CDPAddrRecordIPv4].addr = self.src_ip
        fakepkt = fakepkt/CDPMsgGeneric()
        fakepkt[CDPMsgGeneric].type = 26
        fakepkt[CDPMsgGeneric].val = '\x00\x00\x00\x01\x00\x00\x00\x00\xff\xff\xff\xff'
        fakepkt[CDPMsgGeneric].len = len(fakepkt[CDPMsgGeneric])
        fakepkt = fakepkt/CDPMsgGeneric(type=31, len=5, val='\x00')
        fakepkt = fakepkt/CDPMsgGeneric(type=4099, len=5, val='1')
        # re-calculate len & cksum (Maybe not need it as crafted from zero)
        del fakepkt.cksum
        del fakepkt.len
        fakepkt.len = len(fakepkt[CDPv2_HDR]) + 8
        fakepkt = fakepkt.__class__(str(fakepkt))
        return fakepkt

    def cisco_phone(self):
        """
        Build Fake IP-Phone CDP packet
        """
        self.logger.debug('Crafting CDP IP-Phone  packet')
        fakepkt = Dot3()/LLC()/SNAP()/CDPv2_HDR()
        fakepkt[Dot3].dst = '01:00:0c:cc:cc:cc'
        fakepkt[Dot3].src = self.mac
        fakepkt[CDPv2_HDR].msg = CDPMsgDeviceID()
        fakepkt[CDPMsgDeviceID].val = self.name
        fakepkt[CDPMsgDeviceID].len = len(fakepkt[CDPMsgDeviceID])
        fakepkt = fakepkt/CDPMsgSoftwareVersion()
        fakepkt[CDPMsgSoftwareVersion].val = self.version
        fakepkt[CDPMsgSoftwareVersion].len = len(fakepkt[CDPMsgSoftwareVersion])
        fakepkt[CDPMsgPlatform].val = self.platform
        fakepkt = fakepkt/CDPMsgPlatform()
        fakepkt[CDPMsgPlatform].len = len(fakepkt[CDPMsgPlatform])
        fakepkt = fakepkt/CDPMsgAddr()
        fakepkt[CDPMsgAddr].naddr = 1
        fakepkt[CDPMsgAddr].addr = CDPAddrRecordIPv4()
        fakepkt[CDPMsgAddr][CDPAddrRecordIPv4].addr = self.src_ip
        fakepkt = fakepkt/CDPMsgPortID()
        fakepkt[CDPMsgPortID].iface = self.port
        fakepkt[CDPMsgPortID].len = len(fakepkt[CDPMsgPortID])
        fakepkt = fakepkt/CDPMsgCapabilities(cap=1168)
        fakepkt = fakepkt/CDPMsgGeneric()
        fakepkt[CDPMsgGeneric].type = 28
        fakepkt[CDPMsgGeneric].val = '\x00\x02\x00'
        fakepkt[CDPMsgGeneric].len = len(fakepkt[CDPMsgGeneric])
        fakepkt = fakepkt/CDPMsgUnknown19()
        fakepkt[CDPMsgUnknown19].type = 25
        fakepkt[CDPMsgUnknown19].val = 'y\x85\x00\x00\x00\x00.\xe0'
        fakepkt[CDPMsgUnknown19].len = len(fakepkt[CDPMsgUnknown19])
        fakepkt = fakepkt/CDPMsgDuplex(duplex=1)
        fakepkt = fakepkt/CDPMsgPower(type=16, power=12000)
        # re-calculate len & cksum (Maybe not need it as crafted from zero)
        del fakepkt.cksum
        del fakepkt.len
        fakepkt.len = len(fakepkt[CDPv2_HDR]) + 8
        fakepkt = fakepkt.__class__(str(fakepkt))
        return fakepkt

    def run(self):
        while not self.stoprequest.isSet():
            if self.type == 'switch':
                sendp(self.cisco_ios(), verbose=0, iface=self.iface)
            elif self.type == 'phone':
                sendp(self.cisco_phone(), verbose=0, iface=self.iface)
            time.sleep(60)

    def join(self):
        self.stoprequest.set()
