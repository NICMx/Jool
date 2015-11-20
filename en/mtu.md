---
language: en
layout: default
category: Documentation
title: MTU and Fragmentation
---

[Documentation](documentation.html) > [Miscellaneous](documentation.html#miscellaneous) > MTU and Fragmentation

# MTU and Fragmentation

## Problem Statement

There's one major difference between IPv4 and IPv6 which an IP Translator alone cannot make up for.

The IPv4 header "features" a flag called [_Don't Fragment_](http://en.wikipedia.org/wiki/IPv4#Packet_structure) (DF). It dictates whether the source allows routers to fragment the packet.

In IPv6, packets can never be fragmented by routers. It's as if DF was always on.

When there's a translator in the middle, an IPv4 packet which can be fragmented becomes an IPv6 packet that must not be fragmented.

So what happens if the packet is too big?

(Actual packet sizes are different due to headers changes, but you get the point.)

![Fig.1 - MTU flow fail](../images/flow/mtu-frag-fail-en.svg)

It's implementation defined. If _n4_ is smart, it will try to decrease the lenght of the packet. If it's not, the packet will never reach _n6_.

Proper implementations today actually use [Path MTU discovery](http://en.wikipedia.org/wiki/Path_MTU_Discovery) and therefore never unset the DF flag. Still, stubborn or legacy code is not unheard of.

By the way: when you want to know a link's MTU, ask Linux:

<div class="highlight"><pre><code class="bash">$ ip link
(...)
2: eth0: &lt;BROADCAST,MULTICAST,UP,LOWER_UP&gt; <strong>mtu 1500</strong> qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:bf:a6:6e brd ff:ff:ff:ff:ff:ff
</code></pre></div>

## Solution

If you know the smallest MTU across all your IPv6 networks, tell _T_ about it:

![Fig.2 - Proper Network](../images/network/mtu-frag.svg)

_T_ knows it's translating, so it knows it **has** to fragment even though it's sort of an IPv6 router.

Jool used to have a flag called `--minMTU6` to do this. Because deferring fragmentation to the kernel is considered better practice, you now configure it on Linux starting from Jool 3.3.

	ip link set dev eth0 mtu 1300

And voilà:

![Fig.3 - MTU flow succeeds](../images/flow/mtu-frag-success-en.svg)

If you don't know the minimum MTU of your IPv6 networks, assign 1280. Every IPv6 node must be able to handle at least 1280 bytes per packet by standard.

