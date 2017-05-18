---
language: en
layout: default
category: Documentation
title: Stateful NAT64 Run
---

[Documentation](documentation.html) > [Basic Tutorials](documentation.html#basic-tutorials) > Stateful NAT64

# Stateful NAT64 Run

## Index

1. [Introduction](#introduction)
2. [Sample Network](#sample-network)
3. [Jool](#jool)
4. [Testing](#testing)
5. [Stopping Jool](#stopping-jool)
6. [Further reading](#further-reading)

## Introduction

This document explains how to run Jool in [Stateful NAT64 mode](intro-xlat.html#stateful-nat64).

Software-wise, only a [successful install of the kernel module](install-mod.html) is required. The userspace application is not needed in this basic run.

## Sample Network

![Figure 1 - Sample Network](../images/network/stateful.svg)

All the remarks in the first document's [Sample Network section](run-vanilla.html#sample-network) apply here.

Nodes _A_ through _E_:

{% highlight bash %}
user@A:~# service network-manager stop
user@A:~# /sbin/ip link set eth0 up
user@A:~# # Replace "::8" depending on which node you're on.
user@A:~# /sbin/ip address add 2001:db8::8/96 dev eth0
user@A:~# /sbin/ip route add default via 2001:db8::1
{% endhighlight %}

Nodes _V_ through _Z_:

{% highlight bash %}
user@V:~# service network-manager stop
user@V:~# /sbin/ip link set eth0 up
user@V:~# # Replace ".16" depending on which node you're on.
user@V:~# /sbin/ip address add 203.0.113.16/24 dev eth0
{% endhighlight %}

Notice these nodes do not need a default route. This is a consequence of them being in the same network as the NAT64; _T_ will be masking the IPv6 nodes, so _V_ through _Z_ think they're talking directly to it.

Node _T_:

{% highlight bash %}
user@T:~# service network-manager stop
user@T:~# 
user@T:~# /sbin/ip link set eth0 up
user@T:~# /sbin/ip address add 2001:db8::1/96 dev eth0
user@T:~# 
user@T:~# /sbin/ip link set eth1 up
user@T:~# /sbin/ip address add 203.0.113.1/24 dev eth1
user@T:~# 
user@T:~# sysctl -w net.ipv4.conf.all.forwarding=1
user@T:~# sysctl -w net.ipv6.conf.all.forwarding=1
user@T:~# 
user@T:~# ethtool --offload eth0 gro off
user@T:~# ethtool --offload eth0 lro off
user@T:~# ethtool --offload eth1 gro off
user@T:~# ethtool --offload eth1 lro off
{% endhighlight %}

> ![Note!](../images/bulb.svg) In previous versions of Jool, _T_ used to need two or more IPv4 addresses. Because pool4 now stores port ranges, this is no longer the case.

Remember you might want to cross-ping _T_ vs everything before continuing.

## Jool

This is the insertion syntax:

	user@T:~# /sbin/modprobe jool \
			[pool6=<IPv6 prefix>] \
			[pool4=<IPv4 prefixes>] \
			[disabled]

See [Kernel Module Options](mod-flags.html#nat64-jool) for a description of each argument.

The result looks like this:

	user@T:~# /sbin/modprobe jool pool6=64:ff9b::/96

Jool will append and remove prefix `64:ff9b::/96`.

> ![Note!](../images/bulb.svg) In previous versions of Jool, `pool4` used to be mandatory. This is no longer the case.

> ![Note!](../images/bulb.svg) Because we skipped the `pool4` argument, Jool will fall back to mask packets using the upper ports of `203.0.113.1`. Unless you have few IPv6 clients, this is probably not what you want. See [pool4](pool4.html) for details on how to fine-tune this.

## Testing

If something doesn't work, try the [FAQ](faq.html).

Test by sending requests from the IPv6 network:

{% highlight bash %}
user@C:~$ ping6 64:ff9b::203.0.113.16
PING 64:ff9b::203.0.113.16(64:ff9b::cb00:7110) 56 data bytes
64 bytes from 64:ff9b::cb00:7110: icmp_seq=1 ttl=63 time=1.13 ms
64 bytes from 64:ff9b::cb00:7110: icmp_seq=2 ttl=63 time=4.48 ms
64 bytes from 64:ff9b::cb00:7110: icmp_seq=3 ttl=63 time=15.6 ms
64 bytes from 64:ff9b::cb00:7110: icmp_seq=4 ttl=63 time=4.89 ms
^C
--- 64:ff9b::203.0.113.16 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 1.136/6.528/15.603/5.438 ms
{% endhighlight %}

![Figure 1 - IPv4 TCP from an IPv6 node](../images/run-stateful-firefox-4to6.png)

> ![Note!](../images/bulb.svg) Obviously, users should not need to be aware of IP addresses, much less know they need to append a prefix whenever they need to speak to IPv4. The [DNS64 document](dns64.html) will tell you how to make the prefix-address-hack transparent to users.

> ![Note!](../images/bulb.svg) Because a NAT64 is stateful, only IPv6-started tests can be run at this point. See [port forwarding](bib.html) if 4-to-6 translation is relevant for you.

## Stopping Jool

To shut down Jool, revert the modprobe using the `-r` flag:

{% highlight bash %}
user@T:~# /sbin/modprobe -r jool
{% endhighlight %}

## Further Reading

More complex setups might require you to consider the [MTU notes](mtu.html).

Please note that none of what was done in this tutorial survives reboots! Documentation on persistence will be released in the future.

The [next tutorial](dns64.html) explains DNS64.
