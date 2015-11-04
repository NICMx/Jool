---
language: en
layout: default
category: Documentation
title: BIB
---

[Documentation](documentation.html) > [NAT64 in Detail](documentation.html#nat64-in-detail) > BIB

# BIB

The _Binding Information Base_ (BIB) is a collection of tables in a stateful NAT64. It is defined in [RFC 6146](http://tools.ietf.org/html/rfc6146#section-3.1). Hopefully, this document can serve as a friendly overview.

Records in this database map the IPv6 transport addresses of a IPv6 node's connection to the IPv4 transport address Jool is using to mask it. For example, if the following mapping exists in your NAT64:

| IPv6 transport address | IPv4 transport address | Protocol |
|------------------------|------------------------|----------|
| 6::6#66                | 4.4.4.4#44             | TCP      |

Then IPv4 nodes can find the TCP service published in 6::6 on port 66, by querying 4.4.4.4 on port 44. In other words, Jool fools IPv4 nodes into thinking that 6::6#66 is 4.4.4.4#44.

Notice the IPv4 column is always a transport address assigned to Jool (ie. it belongs to [`pool4`](pool4.html)). This is because the mappings are only talking about IPv6 nodes; Jool is not fooling the IPv6 domain into thinking that 4.4.4.4#44 is 6::6#66. (You don't mask the IPv4 Internet; the IPv6 version of an IPv4 node's address is always the `pool6` prefix plus the original v4 address.)

* We call "BIB entry" a record in a BIB table (ie. a descriptor of a mask).
* We call "BIB table" a collection of records which share a protocol. There are three supported protocols (TCP, UDP and ICMP), therefore Jool has three BIB tables.
* We call "BIB" the collection of Jool's three BIB tables.

There are two types of BIB entries:

* Dynamic: Whenever an IPv6 node wants to speak to an IPv4 one, Jool has to create a mask so communication can take place. This mask is a BIB entry. Jool creates and destroys these on the fly.
* Static: You create them manually, to publish an IPv6 service to the IPv4 Internet. This is analogous to <a href="http://en.wikipedia.org/wiki/Port_forwarding" target="_blank">port forwarding</a> in normal NATs.

You can view Jool's current BIB table by running `jool --bib --display` (and to speed things up, add `--numeric`). See [`--bib`](usr-flags-bib.html) for more information on how to further interact with the table. See [`--address-dependent-filtering`](usr-flags-global.html#address-dependent-filtering) if you think dynamic entries are dangerous.

