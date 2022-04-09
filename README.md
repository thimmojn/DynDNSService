# Simple dynamic DNS update service

This Python based web service provides a simple DNS update mechanism. It is intend for routers, which dynamic IP address should be accessible by a fixed domain.

The update URL has a standard structure:

    https://ddns.example.com?domain=<DOMAIN>[&ip4=<IPv4>][&ip6=<IPv6>][&me=true]

There can be a IPv4 address, a IPv6 address or both provided. If no address is provided, nothing will be changed. Additionally the `me` flag can be set. In this mode client's IP address will be used. A explicitly given IP address via `ip4` or `ip6` overwrites the determined address. The client uses basic authentication.

A proper configured DNS server is required, which allows dynamic zone updates with a key over TCP.
