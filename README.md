# Simple dynamic DNS update service

This Python based web service provides a simple DNS update mechanism. It is intend for routers, which dynamic IP address should be accessible by a fixed domain.

The update URL has a standard structure:

    https://ddns.example.com?domain=<DOMAIN>&ip4=<IPv4>&ip6=<IPv6>

There is at least a IPv4 address or IPv6 address required. The client uses basic authentication.

A proper configured DNS server is required, which allows dynamic zone updates with a key over TCP.
