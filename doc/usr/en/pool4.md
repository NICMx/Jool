---
language: en
layout: default
category: Documentation
title: IPv4 Transport Address Pool
---

[Documentation](documentation.html) > [NAT64 in Detail](documentation.html#nat64-in-detail) > The IPv4 Transport Address Pool

# IPv4 Transport Address Pool

## Index

1. [Introduction](#introduction)
2. [Quick version](#quick-version)
3. [Long version](#long-version)

## Introduction

This document serves as a general explanation of NAT64 Jool's pool4.

## Quick version

If you're familiar with iptables and masquerade, all you probably need to know is that the following:

	jool --pool4 --add --tcp 192.0.2.1 5000-6000

is spiritually equivalent to

	ip addr add 192.0.2.1 dev (...)
	iptables -t nat -A POSTROUTING -p TCP -j MASQUERADE --to-ports 5000-6000

## Long version

Just like a NAT, a Stateful NAT64 allows an indeterminate amount of clients to share a few IPv4 addresses by strategically distributing their traffic accross its own transport address domain.

We call this "transport address domain" the "IPv4 pool" ("pool4" for short).

To illustrate:

![Fig. 1 - n6's request](../images/flow/pool4-simple1-en.svg "Fig. 1 - n6's request")

In Jool, we write transport addresses in the form `<IP address>#<port>` (as opposed to `<IP address>:<port>`). The packet above has source IP address `2001:db8::8`, source port (TCP or UDP) 5123, destination address `64:ff9b::192.0.2.24`, and destination port 80.

Assuming pool4 holds transport addresses `192.0.2.1#5000` through `192.0.2.1#6000`, one possible translation of the packet is this:

![Fig. 2 - T's translation - version 1](../images/flow/pool4-simple2-en.svg "Fig. 2 - T's translation - version 1")

Another one, equally valid, is this:

![Fig. 3 - T's translation - version 2](../images/flow/pool4-simple3-en.svg "Fig. 3 - T's translation - version 2")

NAT64s are not overly concerned with retaining source ports. In fact, for security reasons, [recommendations exist to drive NAT64s as unpredictable as possible in this regard]({{ site.draft-nat64-port-allocation }}).

When defining the addresses and ports that will belong to your pool4, you need to be aware that they must not collide with other services or clients within the same machine. If _T_ tries to open a connection from transport address `192.0.2.1#5000` and at the same time a translation yields source transport address `192.0.2.1#5000`, Jool will end up combining the the information transmitted in both connections.

If you have no elements in pool4 whatsoever, Jool will fall back to mask packets using the primary global addresses configured in its node's interfaces. Because Linux's ephemeral port range defaults to 32768-61000, Jool will only attempt to mask packets using ports 61001-65535 in this case.

On the other hand, if you insert elements to pool4 and do not specify port ranges, Jool will assume it can use the entire port domain of the addresses (1-65535). This is done for backwards compatibility reasons.

[You can change Linux's ephemeral port range by tweaking sysctl `sys.net.ipv4.ip_local_port_range`, and pool4's port range by means of `--pool4 --add` userspace application commands](usr-flags-pool4.html#notes).

