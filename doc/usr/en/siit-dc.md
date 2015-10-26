---
language: en
layout: default
category: Documentation
title: SIIT-DC
---

[Documentation](documentation.html) > [Architectures](documentation.html#architectures) > SIIT-DC

# SIIT-DC

## Index

1. [Introduction](#introduction)
2. [Sample Network](#sample-network)
3. [Configuration](#configuration)

## Introduction

This document is a summary of the [_SIIT-DC_ architecture]({{ site.draft-siit-dc }}), and a small walkthrough that builds it using Jool.

SIIT-DC is an improvement over traditional SIIT where EAMs are introduced and standardized. With this, IPv4 address usage is optimized and IPv4 address embedding (in IPv6 servers) becomes redundant.

## Sample Network

This is the sample architecture from [draft-siit-dc section 3]({{ site.draft-siit-dc }}#section-3):

![Fig.1 - Network Overview](../images/network/siit-dc.svg "Fig.1 - Network Overview")

_n6_ is a random IPv6 node. _s6_ is one of your Data Centre servers (IPv6). _n4_ is a random IPv4 node. _BR_ ("Border Relay") is an SIIT.

`2001:db8:46::/96` is routed to _BR_'s Data Centre-facing interface, and similarly, `192.0.2.1/32` (or covering aggregate) is routed to _BR_'s IPv4 Internet-facing interface. This is done using standard IP routing techniques.

The jist of SIIT-DC is _n6_ can use _s6_'s IPv6-only service using normal IPv6 connectivity, while _n4_ can use it via _BR_.

This will be the expected packet flow for _n6_:

![Fig.2 - n6 Packet Flow](../images/flow/siit-dc-n6.svg "Fig.2 - n6 Packet Flow")

And this will be the expected packet flow for _n4_:

![Fig.3 - n4 Packet Flow](../images/flow/siit-dc-n4.svg "Fig.3 - n4 Packet Flow")

Some properties of this are:

- Mostly Single (IPv6) Stack operation (in the Data Centre). This simplifies maintenance as running one protocol is simpler than two.
- Native IPv6 traffic is never modified at all.
- Scales elegantly (Fully stateless operation, which can be made redundant painlessly).
- Can optimize IPv4 address usage within the Data Centre (because it doesn't impose restrictions on the servers' IPv6 addresses).
- Promotes IPv6 deployment (IPv4 end-user connectivity becomes a service provided by the network).
- If you want to stop needing IPv4 in the future, all you need to do is shut down _BR_.

## Configuration

Networking commands aside, this is Jool on _BR_:

{% highlight bash %}
# modprobe jool_siit pool6=2001:db8:46::/96
# jool_siit --eamt --add 192.0.2.1 2001:db8:12:34::1
{% endhighlight %}

For every server you want to publish on IPv4, you add one EAMT entry (as above) and appropriate IPv4 DNS records.

