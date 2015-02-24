---
layout: documentation
title: Documentation - Stateful NAT64 Run
---

[Documentation](doc-index.html) > [Runs](doc-index.html#runs) > Stateful NAT64

# Stateful Run

## Index

1. [Introduction](#introduction)
2. [Sample Network](#sample-network)
3. [Jool](#jool)
4. [Testing](#testing)
5. [Stopping Jool](#stopping-jool)
6. [Further reading](#further-reading)

## Introduction

This document explains how to run Jool in [stateful mode](intro-nat64.html#stateful-nat64).

Software-wise, only a [successful install of the kernel module](mod-install.html) is required. The userspace application is not needed in this basic run.

## Sample Network

![Figure 1 - Sample Network](images/intro/network-4stateful.svg)

All the remarks in the first document's [Sample Network section](mod-run-vanilla.html#sample-network) apply here.

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
user@V:~# /sbin/ip address add 192.0.2.16/24 dev eth0
user@V:~# /sbin/ip route add default via 192.0.2.2
{% endhighlight %}

Notice we changed the default route. See below for the rationale.

Node _N_:

{% highlight bash %}
user@N:~# service network-manager stop
user@N:~# 
user@N:~# /sbin/ip link set eth0 up
user@N:~# /sbin/ip address add 2001:db8::1/96 dev eth0
user@N:~# 
user@N:~# /sbin/ip link set eth1 up
user@N:~# /sbin/ip address add 192.0.2.1/24 dev eth1
user@N:~# /sbin/ip address add 192.0.2.2/24 dev eth1
user@N:~# 
user@N:~# sysctl -w net.ipv4.conf.all.forwarding=1
user@N:~# sysctl -w net.ipv6.conf.all.forwarding=1
user@N:~# 
user@N:~# ethtool --offload eth0 tso off
user@N:~# ethtool --offload eth0 ufo off
user@N:~# ethtool --offload eth0 gso off
user@N:~# ethtool --offload eth0 gro off
user@N:~# ethtool --offload eth0 lro off
user@N:~# ethtool --offload eth1 tso off
user@N:~# ethtool --offload eth1 ufo off
user@N:~# ethtool --offload eth1 gso off
user@N:~# ethtool --offload eth1 gro off
user@N:~# ethtool --offload eth1 lro off
{% endhighlight %}

Stateful mode is special in that the NAT64 needs at least two separate IPv4 addresses:

- One or more addresses used for local traffic (ie. to and from _N_). In the configuration above, this is 192.0.2.1.
- One or more addresses used for NAT64 translation. Linux needs to be aware of these because it needs to ARP reply them. This one is 192.0.2.2.

The need for this separation _is a Jool quirk_ and we're still researching ways to remove it.

The translation addresses need less priority so _N_ doesn't use them for local traffic by accident. One way to achieve this is to simply add the NAT64 addresses after the node addresses.

Remember you might want to cross-ping _N_ vs everything before continuing.

## Jool

{% highlight bash %}
user@N:~# /sbin/modprobe jool_stateful pool6=64:ff9b::/96 pool4=192.0.2.2
{% endhighlight %}

- `pool6` has the same meaning as in stateless Jool.
- `pool4` is the subset of the node's addresses which will be used for translation (the prefix length defaults to /32).

EAM and `errorAddresses` do not make sense in stateful mode, and as such are unavailable.

## Testing

If something doesn't work, try the [FAQ](misc-faq.html).

Test by sending requests from the IPv6 network:

{% highlight bash %}
user@C:~$ ping6 64:ff9b::192.0.2.16
PING 64:ff9b::192.0.2.16(64:ff9b::c000:210) 56 data bytes
64 bytes from 64:ff9b::c000:210: icmp_seq=1 ttl=63 time=1.13 ms
64 bytes from 64:ff9b::c000:210: icmp_seq=2 ttl=63 time=4.48 ms
64 bytes from 64:ff9b::c000:210: icmp_seq=3 ttl=63 time=15.6 ms
64 bytes from 64:ff9b::c000:210: icmp_seq=4 ttl=63 time=4.89 ms
^C
--- 64:ff9b::192.0.2.16 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 1.136/6.528/15.603/5.438 ms
{% endhighlight %}

![Figure 1 - IPv4 TCP from an IPv6 node](images/run-stateful-firefox-4to6.png)

See the further reading below to see how to enable IPv4 nodes to start communication.

## Stopping Jool

To shut down Jool, revert the modprobe using the `-r` flag:

{% highlight bash %}
user@N:~# /sbin/modprobe -r jool_stateful
{% endhighlight %}

## Further Reading

1. An IPv4 "outside" node cannot start communication because it "sees" the IPv6 network as an IPv4 private network behind a NAT. To remedy this, Jool enables you to configure "port forwarding". See [here](op-static-bindings.html) if you're interested.
2. There's a discussion on the [IPv4 pool](op-pool4.html).
3. The [DNS64 document](op-dns64.html) will tell you how to make the prefix-address-hack transparent to users.

