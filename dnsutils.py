# -*- encoding: utf-8-unix -*-

import dns.name, dns.query, dns.rcode, dns.rdatatype, dns.resolver, dns.tsig, dns.update
import ipaddress
from socket import AddressFamily
from typing import Optional, Union


class DomainUpdate:
    def __init__(self, domain: str, tsigKey: dns.tsig.Key, dnsServer: str):
        self.domainName = dns.name.from_text(domain)
        zone = self.domainName.parent()
        self.hostName = self.domainName.relativize(zone)
        # prepare DNS update
        self._request = dns.update.Update(zone, keyring=tsigKey)
        # target DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [dnsServer]

    @property
    def dirty(self) -> bool:
        """Returns true, if there are record updates."""
        return len(self._request.update) > 0

    def addIPAddress(self, ipv4or6Address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]):
        rdType = DNSUtils.rdataTypeByIPAddress(ipv4or6Address)
        try:
            currentAddress = self.resolver.resolve(self.domainName, rdType)
            if ipaddress.ip_address(currentAddress[0].address) != ipv4or6Address:
                # update record
                self._request.present(self.hostName, rdType)
                self._request.replace(self.hostName, 300, rdType, str(ipv4or6Address))
        except dns.resolver.NXDOMAIN:
            # create record
            self._request.absent(self.hostName, rdType)
            self._request.add(self.hostName, 300, rdType, str(ipv4or6Address))

    def send(self) -> bool:
        # are updates available?
        if not self.dirty:
            raise ValueError("nothing to update")
        # send update request
        response = dns.query.tcp(self._request, self.resolver.nameservers[0])
        return response.rcode() == dns.rcode.NOERROR


class DNSUtils:
    def rdataTypeByIPAddress(address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> dns.rdatatype.RdataType:
        if isinstance(address, ipaddress.IPv4Address):
            return dns.rdatatype.A
        elif isinstance(address, ipaddress.IPv6Address):
            return dns.rdatatype.AAAA
        else:
            raise ValueError('unhandled address family: {}'.format(type(address)))

    @staticmethod
    def isValidIPAddress(address: str, version: Optional[int]=None, mustGlobal: bool=True) -> bool:
        try:
            ipAddress = ipaddress.ip_address(address)
            # validate version and global one if necessary
            return (version is None or ipAddress.version == version) \
                and (not mustGlobal or ipAddress.is_global)
        except ValueError:
            # address string is no IP address
            return False
