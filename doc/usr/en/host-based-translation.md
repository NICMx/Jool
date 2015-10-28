---
language: en
layout: default
category: Documentation
title: Userspace Application Flags
---

[Documentation](documentation.html) > [Other Sample Runs](documentation.html#other-sample-runs) > Host-Based Translation

# Host-Based Translation

## Introduction

Sometimes you might want a machine to translate its own traffic. This is usually because you have IPv6-only connectivity, an application that only works on IPv4, and no access to a translator nearby.

Host-Based Translation is a technique that hooks an SIIT or NAT64 layer somewhere between your application and your network interface. The application sends packets normally and the translator converts them before they reach the medium. As stated, the idea is usually to convert IPv4 packets, though the opposite is still possible.

This document introduces a means to achieve such an arragement using Jool.

## Setup

The idea is to wrap Jool within a network namespace and route translating packets towards it. It should look like this:

![Fig. 1 - Sample Network](../images/network/hbet.svg)

_to_jool_ and _to_world_ are interconnected dual-stack virtual interfaces. _to_jool_ is named such because it is used to reach Jool. _to_world_ belongs to an isolated network namespace (the dotted red square) where Jool is translating traffic, and it's Jool's gateway to everything else.

Application _App_ binds itself to the IPv4 address of _to_jool_, which makes its packets reach Jool. Jool translates and bounces the equivalent IPv6 traffic, which gets routed to _eth0_ normally. If there's a response, the new IPv6 packet traverses the path in reverse until it reaches _App_ as an IPv4 packet.

The overall setup is equivalent to the [single interface sample run](mod-run-alternate.html), except most of the work happens within a single node.

## Configuration

### 1: Create the virtual interfaces and the new namespace

First, create the new namespace:

	$ ip netns add joolns

Then create _i_ and _j_:

	$ ip link add name to_jool type veth peer name to_world
	$ ip link
	$ ip link set to_jool up
	$ ip link set to_world up

Send _j_ to _joolns_:

	$ ip link set dev to_world netns jool

### 2: Determine link-local addresses of veth pair (used as nexthops later)

	$ ip -6 address show scope link dev to_jool
	4: to_jool: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qlen 1000
	    inet6 fe80::2ca5:c7ff:feb5:4f07/64 scope link 
	       valid_lft forever preferred_lft forever
	$ ip netns exec jool ip -6 address show scope link dev to_world
	3: to_world: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qlen 1000
	    inet6 fe80::e8d1:81ff:fee5:2406/64 scope link 
	       valid_lft forever preferred_lft forever

### 3: Set up IP addressing and routing inside Jool namespace

	$ ip netns exec jool ip -6 route add default via fe80::2ca5:c7ff:feb5:4f07 dev to_world
	$ ip netns exec jool ip -4 address add 192.0.0.2/29 dev to_world

### 4: Set up IP addressing and routing in global namespace

The IPv6 CLAT address is stolen from the /64 on eth0, so we'll need proxy-nd

	$ echo 1 > /proc/sys/net/ipv6/conf/eth0/proxy_ndp
	$ ip -6 neigh add proxy 2a02:c0:400:104::4646 dev eth0
	$ ip -6 route add 2a02:c0:400:104::4646 via fe80::e8d1:81ff:fee5:2406 dev to_jool
	$ ip -4 address add 192.0.0.1/29 dev to_jool
	$ ip -4 route add default via 192.0.0.2 dev to_jool
	$ echo 1 | tee /proc/sys/net/ipv6/conf/*/forwarding

### 5: Fire up Jool inside network namespace

	$ ip netns exec jool modprobe jool_siit
	$ ip netns exec jool jool_siit --pool6 --add 2001:67c:2b0:db32:0:1::/96
	$ ip netns exec jool jool_siit --eamt --add 192.0.0.1 2a02:c0:400:104::4646

### 6: Confirm that it works:

	$ ping -c1 8.8.8.8
	PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
	64 bytes from 8.8.8.8: icmp_seq=1 ttl=47 time=26.5 ms

	--- 8.8.8.8 ping statistics ---
	1 packets transmitted, 1 received, 0% packet loss, time 0ms
	rtt min/avg/max/mdev = 26.520/26.520/26.520/0.000 ms
	$ mtr -r -c 10 8.8.8.8
	Start: Thu Oct  1 09:50:23 2015
	HOST: kvmtest.i.bitbit.net        Loss%   Snt   Last   Avg  Best  Wrst StDev
	  1.|-- 192.0.0.2                  0.0%    10    0.1   0.2   0.1   0.4   0.0
	  2.|-- 192.0.0.2                  0.0%    10    0.2   0.3   0.2   0.3   0.0
	  3.|-- 192.0.0.2                  0.0%    10    0.7   0.6   0.5   1.0   0.0
	  4.|-- 192.0.0.2                  0.0%    10    1.6   1.6   1.4   1.8   0.0
	  5.|-- 192.0.0.2                  0.0%    10    0.8   0.7   0.6   1.0   0.0
	  6.|-- 192.0.0.2                  0.0%    10    0.8   0.8   0.7   1.1   0.0
	  7.|-- 192.0.0.2                  0.0%    10    7.6   7.7   7.5   7.9   0.0
	  8.|-- 192.0.0.2                  0.0%    10   13.4  13.6  13.4  13.9   0.0
	  9.|-- 192.0.0.2                  0.0%    10   16.9  17.0  16.8  17.7   0.0
	 10.|-- 192.0.0.2                  0.0%    10   16.7  16.9  16.6  17.4   0.0
	 11.|-- 192.0.0.2                  0.0%    10   16.9  16.9  16.9  17.1   0.0
	 12.|-- 192.0.0.2                  0.0%    10   16.8  17.0  16.8  17.5   0.0
	 13.|-- hanna.bb.trex.fi           0.0%    10   17.5  17.5  17.4  18.0   0.0
	 14.|-- eunetip1.unicast.trex.fi   0.0%    10   20.6  20.6  20.4  20.9   0.0
	 15.|-- 213.192.184.74             0.0%    10   26.2  26.7  26.2  27.8   0.0
	 16.|-- 74.125.50.145              0.0%    10   33.2  27.3  26.0  33.2   2.2
	 17.|-- 216.239.54.181             0.0%    10   26.6  26.9  26.6  27.7   0.0
	 18.|-- 209.85.251.227             0.0%    10   26.6  26.6  26.4  26.9   0.0
	 19.|-- google-public-dns-a.googl  0.0%    10   26.2  26.4  26.2  26.8   0.0

