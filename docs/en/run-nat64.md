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
6. [Afterwords](#afterwords)

## Introduction

This document explains how to run Jool in [Stateful NAT64 mode](intro-xlat.html#stateful-nat64).

## Sample Network

![Figure 1 - Sample Network](../images/network/stateful.svg)

All the remarks in the first document's [Sample Network section](run-vanilla.html#sample-network) apply here.

Nodes _A_ through _E_:

{% highlight bash %}
user@A:~# service network-manager stop
user@A:~# /sbin/ip link set eth0 up
user@A:~# # Replace "::8" depending on which node you're on.
user@A:~# /sbin/ip address add 2001:db8::8/96 dev eth0
user@A:~# /sbin/ip route add 64:ff9b::/96 via 2001:db8::1
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
{% endhighlight %}

> ![Note!](../images/bulb.svg) In previous versions of Jool, _T_ used to need two or more IPv4 addresses. Because pool4 now stores port ranges, this is no longer the case.

Remember you might want to cross-ping _T_ vs everything before continuing.

## Jool

Even though they share a lot of code, because of kernel quirks, the NAT64 module is separate from the SIIT one. The name of the NAT64 module is `jool`.

{% highlight bash %}
user@T:~# /sbin/modprobe jool
{% endhighlight %}

Though the meaning of `pool6` is slightly different than in SIIT, the instance configuration looks pretty much the same:

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">iptables Jool</span>
	<span class="distro-selector" onclick="showDistro(this);">Netfilter Jool</span>
</div>

<!-- iptables Jool -->
{% highlight bash %}
user@T:~# jool instance add "example" --iptables  --pool6 64:ff9b::/96
user@T:~#
user@T:~# ip6tables -t mangle -A PREROUTING -j JOOL --instance "example"
user@T:~# iptables  -t mangle -A PREROUTING -j JOOL --instance "example"
{% endhighlight %}

<!-- Netfilter Jool -->
{% highlight bash %}
user@T:~# jool instance add "example" --netfilter --pool6 64:ff9b::/96
 

 
{% endhighlight %}

The iptables configuration, on the other hand, needs to use the `JOOL` target.

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

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">iptables Jool</span>
	<span class="distro-selector" onclick="showDistro(this);">Netfilter Jool</span>
</div>

<!-- iptables Jool -->
{% highlight bash %}
user@T:~# ip6tables -t mangle -D PREROUTING -j JOOL --instance "example"
user@T:~# iptables  -t mangle -D PREROUTING -j JOOL --instance "example"
user@T:~# jool instance remove "example"
user@T:~# /sbin/modprobe -r jool
{% endhighlight %}

<!-- Netfilter Jool -->
{% highlight bash %}
 
 
user@T:~# jool instance remove "example"
user@T:~# /sbin/modprobe -r jool
{% endhighlight %}

## Afterwords

1. More complex setups might require you to consider the [MTU notes](mtu.html).
3. Please note that none of what was done in this tutorial survives reboots! [Here](run-persistent.html)'s documentation on persistence.

The [next tutorial](dns64.html) explains DNS64.
