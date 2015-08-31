---
language: en
layout: default
category: Documentation
title: IPv4 Transport Address Pool
---

[Documentation](documentation.html) > [Runs](documentation.html#runs) > [Stateful NAT64](mod-run-stateful.html) > IPv4 Pool

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

We call this "transport address domain" the "IPv4 pool" ("pool4" for short), and it's one of the two mandatory requirements for NAT64 translation (the other being pool6). Without elements in pool4, there's nothing to mask packets with.

To illustrate:

![TODO](../images/flow/pool4-simple1-en.svg)

In Jool, we write transport addresses in the form `<IP address>#<port>` (as opposed to `<IP address>:<port>`). The packet above has source IP address `2001:db8::8`, source port (TCP or UDP) 5123, destination address `64:ff9b::192.0.2.24`, and destination port 80.

Assuming pool4 holds transport addresses `203.0.113.1#5000` through `203.0.113.1#6000`, one possible translation of the packet is this:

![TODO](../images/flow/pool4-simple2-en.svg)

Another one, equally valid, is this:

![TODO](../images/flow/pool4-simple3-en.svg)

NAT64s are not overly concerned with retaining source ports. In fact, for security reasons, [recommendations exist to drive NAT64s as unpredictable as possible](https://tools.ietf.org/html/rfc6056).

Each connection being translated will borrow a transport address from the pool. If you have _n_ transport addresses in pool4, you can have _n_ simultaneous translating connections. After a connection expires, its transport address becomes re-eligible for assignment.

You can fine-tune your pool4 table by means of the [`--pool4`](usr-flags-pool4.html) userspace configuration mode, and the connection expiration timeouts by tweaking  [`--udp-timeout`](usr-flags-global.html#udp-timeout), [`--tcp-est-timeout`](usr-flags-global.html#tcp-est-timeout), [`--tcp-trans-timeout`](usr-flags-global.html#tcp-trans-timeout) and [`--icmp-timeout`](usr-flags-global.html#icmp-timeout).

