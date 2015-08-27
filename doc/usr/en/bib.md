---
language: en
layout: default
category: Documentation
title: BIB
---

[Documentation](documentation.html) > [Runs](documentation.html#runs) > [Stateful NAT64](mod-run-stateful.html) > BIB

# BIB

The _Binding Information Base_ (BIB) is a collection of tables in a stateful NAT64. It is defined in <a href="http://tools.ietf.org/html/rfc6146#section-3.1" target="_blank">RFC 6146</a>. Hopefully, this document can serve as a friendly overview.

Records in this database map the IPv6 transport addresses of a IPv6 node's connection to the IPv4 transport address Jool is using to mask it. For example, if the following mapping exists in your NAT64:

| IPv6 transport address | IPv4 transport address | Protocol |
|------------------------|------------------------|----------|
| 6::6#66                | 4.4.4.4#44             | TCP      |

Then IPv4 nodes can find the TCP service published in 6::6 on port 66, by querying 4.4.4.4 on port 44. In other words, Jool fools IPv4 nodes into thinking that 6::6#66 is 4.4.4.4#44.

* We call "BIB entry" a record in a BIB table (ie. a descriptor of a mask).
* We call "BIB table" a collection of records which share a protocol. There are three supported protocols (TCP, UDP and ICMP), therefore Jool has three BIB tables.
* We call "BIB" the collection of Jool's three BIB tables.

There are two types of BIB entries:

* Static: You create them manually, to publish a IPv6 service to the IPv4 Internet. This is analogous to <a href="http://en.wikipedia.org/wiki/Port_forwarding" target="_blank">port forwarding</a> in normal NATs.
* Dynamic: Jool creates these on the fly. This has to be done because IPv6-started connections also need IPv4 masks (otherwise they wouldn't be able to receive answers).

See the [walkthrough](static-bindings.html) or the [reference material](usr-flags-bib.html) for information on how to create and destroy entries manually. See [`--address-dependent-filtering`](usr-flags-global.html#address-dependent-filtering) if you think dynamic entries are dangerous.

