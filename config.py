# -*- encoding: utf-8-unix -*-

import dns.tsig, yaml
from passlib.hash import argon2
from typing import Optional
from dnsutils import DNSUtils


class Configuration:
    def __init__(self, data: object):
        self._data = data

    @classmethod
    def load(cls, filename: str) -> "Configuration":
        # load and parse from file
        with open(filename, 'r') as f:
            data = yaml.load(f, Loader=yaml.Loader)
        return cls(data)

    @property
    def realm(self) -> str:
        return str(self._data.get('realm', 'DynDNS'))

    @property
    def dnsServer(self) -> str:
        if 'dnsserver' in self._data:
            if DNSUtils.isValidIPAddress(self._data['dnsserver']):
                return self._data['dnsserver']
            else:
                raise ValueError('dnsserver: invalid IP address')
        else:
            raise ValueError('dnsserver: missing')

    @property
    def tsigKey(self) -> dns.tsig.Key:
        return dns.tsig.Key(**self._data['tsig'])

    def _getDomainInformation(self, domain: str) -> Optional[dict]:
        domainInfo = self._data.get('domains', dict()).get(str(domain), None)
        if domainInfo is not None and not isinstance(domainInfo, dict):
            raise TypeError('invalid entry for domain: {}'.format(domain))
        return domainInfo

    def isAcceptedDomain(self, domain: str) -> bool:
        return self._getDomainInformation(domain) is not None

    def isClientAuthorized(self, domain: str, username: str, password: str) -> bool:
        # get client authentification information
        domainInfo = self._getDomainInformation(domain)
        if domainInfo is None:
            raise ValueError('no client authentification information provided')
        # extract username and password hash
        requiredUsername = domainInfo.get('username', None)
        passwordHash = domainInfo.get('password', None)
        if type(requiredUsername) != str or type(passwordHash) != str:
            raise TypeError('missing or invalid username or password hash for domain {}'.format(domain))
        # check username and password
        return requiredUsername == username and argon2.verify(password, passwordHash)

    def getRealDomain(self, domain: str) -> str:
        domainInfo = self._getDomainInformation(domain)
        return domainInfo.get('domain', domain)
