# -*- encoding: utf-8-unix -*-

from flask import abort, Flask, request, Response
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
def runUpdate():
    # what domain should be updated?
    domain = request.args.get('domain', '')
    # is domain update allowed?
    if not config.isAcceptedDomain(domain):
        abort(404, 'domain not found')
    # only authorized clients are allowed to update
    if request.authorization is None:
        abort(401)
    # check username and password
    if not config.isClientAuthorized(domain, **request.authorization):
        abort(403)
    # get IPv4 and IPv6 address
    ip4 = request.args.get('ip4', None)
    ip6 = request.args.get('ip6', None)
    if ip4 is None and ip6 is None:
        app.logger.error('no IPv4 or IPv6 address given')
        abort(400, 'need at least IPv4 or IPv6 address')
    # check IP addresses
    if ip4 is not None and not DNSUtils.isValidIPAddress(ip4, 4):
        app.logger.error('invalid IPv4 address')
        abort(400, 'invalid IPv4 address')
    if ip6 is not None and not DNSUtils.isValidIPAddress(ip6, 6):
        app.logger.error('invalid IPv6 address')
        abort(400, 'invalid IPv6 address')
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
