---
language: en
layout: default
category: Documentation
title: SIIT-DC
---

[Documentation](documentation.html) > [Architectures](documentation.html#architectures) > SIIT-DC: Dual Translation Mode

# SIIT-DC: Dual Translation Mode

## Index

## Introduction

This document is a summary of the _SIIT-DC: Dual Translation Mode_ (SIIT-DC-DTM) architecture, and a small walkthrough that builds it using Jool.

SIIT-DC-DTM is an optional improvement over [SIIT-DC](mod-run-siit-dc.html) which adds a mirror translator to inherit the benefits of [464XLAT](mod-run-464xlat.html).

## Sample Network

This is the sample architecture from [draft-siit-dc-2xlat section 3.2]({{ site.draft-siit-dc-2xlat }}#section-3.2):

![Fig.1 - Network Overview](../images/network/siit-dc-2xlat-overview.svg "Fig.1 - Network Overview")

It's the same as SIIT-DC, except an isolated IPv4 island amidst the IPv6-only Data Centre has been added. _ER_ will revert the translation done by _BR_ so these nodes can seemingly natively communicate with the IPv4 Internet.

You need this if SIIT-DC doesn't suffice because some application in the Data Centre either doesn't support NAT (i.e., the lack of end-to-end transparency of IP addresses) or doesn't support IPv6 at all.

This will be the expected packet flow (in addition to the ones in the [SIIT-DC tutorial](mod-run-siit-dc.html)):

![Fig.2 - Packet Flow](../images/flow/siit-dc-2xlat.svg "Fig.2 - Packet Flow")

## Configuration

![Fig.3 - Collapsed Network](../images/network/siit-dc-2xlat-collapsed.svg "Fig.3 - Collapsed Network")

Start from the [SIIT-DC configuration](mod-run-siit-dc.html#configuration) and add:

{% highlight bash %}
# ip addr add 198.51.100.2/24 dev eth0
# ip addr add 2001:db8:3333::2
# ip route add default via 2001:db8:3333::1
# 
# modprobe jool_siit pool6=2001:db8:46::/96
# jool_siit --eamt --add 192.0.2.1 2001:db8:12:34::1
{% endhighlight %}

If you also want to grant the IPv4 nodes an IPv6 address anyway try instead:

