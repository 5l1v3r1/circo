"""
Link Layer Discovery Protocol (LLDP) Honeypot
"""
import logging
import re
import threading
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.0"


class LLDPHandler(threading.Thread):
    """
    Class to handle LLDP packets, will start in background and send
    packets every 30 seconds, pretend to be a Cisco Phone or Switch
    """
    def __init__(self, iface, mac, src_ip, name, port, model, devicetype):
        # devicetype should be 'switch' or 'phone'
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        load_contrib('lldp')
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
            self.description = ver[:4]
        elif self.type == 'phone':
            self.description = 'SIP75.8-5-3SR1S'

    def generic(self):
        """
        Build Fake LLDP packet for a switch or phone
        """
        pkteth = Ether(dst='01:80:c2:00:00:0e', src=self.mac, type=35020)
        pktchass = LLDPDUChassisID(_type=1, subtype=4, _length=7, id=self.mac)
        pktportid = LLDPDUPortID(_type=2, subtype=5)
        pktportid.id = self.port[:2] + re.findall(r'[0-9/]+', self.port)[0]
        pktportid._length = len(pktportid[LLDPDUPortID].id) + 1
        pktttl = LLDPDUTimeToLive(_type=3, ttl=120, _length=2)
        pktsys = LLDPDUSystemName(_type=5, system_name=self.name)
        pktsys._length = len(pktsys[LLDPDUSystemName].system_name)
        pktdes = LLDPDUSystemDescription(_type=6)
        pktdes.description = self.description
        pktdes._length = len(pktdes[LLDPDUSystemDescription].description)
        pktport = LLDPDUPortDescription(_type=4, description=self.port)
        pktport._length = len(pktport[LLDPDUPortDescription].description)
        pktsyscap = LLDPDUSystemCapabilities(_type=7,
                                             _length=4,
                                             mac_bridge_available=1,
                                             mac_bridge_enabled=1)
        pktmgt = LLDPDUManagementAddress(_type=8, _length=12)
        pktmgt.management_address = (chr(int(self.src_ip.split('.')[0]))
                                     + chr(int(self.src_ip.split('.')[1]))
                                     + chr(int(self.src_ip.split('.')[2]))
                                     + chr(int(self.src_ip.split('.')[3])))
        pktmgt._management_address_string_length = 5
        pktmgt.management_address_subtype = 1
        pktmgt.interface_numbering_subtype = 3
        pktmgt.interface_number = long(100)
        pktmgt._oid_string_length = 0
        pktmgt.object_id = ''
        pkt8021 = LLDPDUGenericOrganisationSpecific(_type=127,
                                                    _length=6,
                                                    org_code=32962,
                                                    subtype=1,
                                                    data='\x00d')
        pkt8023 = LLDPDUGenericOrganisationSpecific(_type=127,
                                                    _length=9,
                                                    org_code=4623,
                                                    subtype=1,
                                                    data='\x03l\x03\x00\x10')
        pktend = LLDPDUEndOfLLDPDU(_type=0, _length=0)
        pkt = pkteth / pktchass / pktportid / pktttl / pktsys / pktdes \
            / pktport / pktsyscap / pktmgt / pkt8021 / pkt8023 / pktend
        return pkt

    def run(self):
        while not self.stoprequest.isSet():
            sendp(self.generic(), iface=self.iface, verbose=0)
            time.sleep(30)

    def join(self):
        self.stoprequest.set()
