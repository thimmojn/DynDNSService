# -*- encoding: utf-8-unix -*-

import ipaddress
from flask import abort, Flask, request, Response
from typing import Optional
from webargs import fields
from webargs.flaskparser import use_kwargs
from config import Configuration
from dnsutils import DNSUtils, DomainUpdate


app = Flask(__name__)
config = Configuration.load('config.yaml')


@app.errorhandler(401)
def unauthorizedWithRealm(error) -> Response:
    return Response('login required', 401, {'WWW-Authenticate': 'Basic realm="{}"'.format(config.realm)})

@app.errorhandler(TypeError)
def typeErrorHandler(error: TypeError) -> Response:
    app.logger.warning('a type error occurred: %s', error)
    return Response('application error', 500)

@app.errorhandler(ValueError)
def valueErrorHandler(error: ValueError) -> Response:
    app.logger.warning('a value error occurred: %s', error)
    return Response('application error', 500)

@app.route('/')
@use_kwargs({
    # what domain should be updated?
    'domain': fields.String(required=True),
    # IPv4 address to reference to
    'ip4': fields.IPv4(missing=None),
    # IPv6 address to reference to
    'ip6': fields.IPv6(missing=None),
    # use client address for ip4 or ip6, but only if the corrospondig address is not given
    'me': fields.Boolean(truthy=None, falsy=None, missing=False)
}, location='query')
def runUpdate(domain: str, ip4: Optional[ipaddress.IPv4Address], ip6: Optional[ipaddress.IPv6Address], me: bool):
    # is domain update allowed?
    if not config.isAcceptedDomain(domain):
        abort(404, 'domain not found')
    # only authorized clients are allowed to update
    if request.authorization is None:
        abort(401)
    # check username and password
    if not config.isClientAuthorized(domain, **request.authorization):
        abort(403)
    # handle client address
    if me:
        requestIPAddress = ipaddress.ip_address(request.remote_addr)
        # use client IP address, will not overwrite explicitly given addresses
        if ip4 is None and isinstance(requestIPAddress, ipaddress.IPv4Address):
            ip4 = requestIPAddress
        elif ip6 is None and isinstance(requestIPAddress, ipaddress.IPv6Address):
            ip6 = requestIPAddress
    # prepare update
    update = DomainUpdate(config.getRealDomain(domain), config.tsigKey, config.dnsServer)
    if ip4 is not None:
        update.addIPAddress(ip4)
    if ip6 is not None:
        update.addIPAddress(ip6)
    # commit update
    if update.dirty:
        if not update.send():
            app.logger.error('DNS update failed')
            abort(400, 'update failed')
        app.logger.info(
            'domain %s updated: IPv4: %s, IPv6: %s',
            domain,
            ip4 if ip4 is not None else '-',
            ip6 if ip6 is not None else '-'
        )
        return 'ok'
    else:
        app.logger.info('domain %s not updated', config.getRealDomain(domain))
        return 'nothing to do'
