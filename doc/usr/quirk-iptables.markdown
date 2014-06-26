---
layout: documentation
title: Documentation - Quirk-iptables
---

# Quirk: The iptables Conundrum

> **Warning.**
> 
> Because the RFC wants us to [fragment outgoing IPv6 packets compulsively](userspace-app.html#minmtu6), we now consider this whole reasoning a fallacy. This quirk will probably go away in the next iteration.

## Index

1. [Theory](#theory)
 1. [IPv4 defrag](#ipv4-defrag)
 2. [defrag and the IPv6 world](#defrag-and-the-ipv6-world)
2. [The current status](#the-current-status)

## Theory

I need to clear something up first: Netfilter is not the same as iptables. Netfilter is a really low level packet manipulation framework (just hooks really) where anything goes, whereas iptables is a more specific one where Linux implements filtering, mangling and NAT. iptables sits on top of Netfilter. It has more tools to develop with, but also more constraints.

(Despite this, both terms are usually used as synonyms because there is usually pretty much one thing sitting on top of Netfilter, and that one thing is iptables.)

Seeing that traditional NAT is implemented on top of iptables, it would seem natural that a NAT64 implementation would do the same. So why is Jool sitting on Netfilter instead?

Because of a corner-case scenario. In order to get to it, I have to backtrack a little:

### IPv4 defrag

In the **IPv4** pipeline, there exists an iptables module normally hooked up to Netfilter, whose name I believe is "<a href="http://lxr.free-electrons.com/source/net/ipv4/netfilter/nf_defrag_ipv4.c?v=3.5" target="_blank">defrag</a>". It is normally the very first step in the chain (as can be seen in the <a href="http://lxr.free-electrons.com/source/include/linux/netfilter_ipv4.h?v=3.5#L57" target="_blank">priority list</a>) and is a life-saver for most of Linux's Network Stack. As its name might imply, its purpose is to assemble incoming fragments so the rest of the code can enjoy relieving privileges such as guaranteed transport headers and the irrelevance of a number of fields in the IP ones.

It is to the point that Linux machines feature the perhaps odd idiosyncrasy of outputting different IPv4 fragments than the ones received, since defrag is normally active even while forwarding. One might argue that this is inefficient since fragmented packets have to first be copied to a single larger buffer and then sliced back, but in reality the end result is probably faster since one gets better "MTU utilization", which is probably more critical than CPU (Also, there's the concept of paged packets, but I'm not sure if it's being used to handle fragments. Anyway, I digress).

The presence of this potential size fluctuation of packets while forwarding in IPv4 is usually painless:

* If an incoming packet's DF flag is off, then who cares if it is sliced back and forth along the way, as long as it is correctly reassembled at the destination.
* If the DF flag is on, then the packet will never be a fragment, so there will be nothing to reassemble. Its size will not change.

NAT depends on conntrack, and conntrack depends on defrag. There's nothing wrong with this; fragments do not affect the major hack which is NAT.

### defrag and the IPv6 world

The problem is that NAT64's nature (specifically, the inclusion of IPv6) stretches NAT's hack a little further. I'm sorry that this will sound very similar to the [offload fiasco](offloading.html), but here it goes:

There is no "IPv6 defrag" module for a reason: There is no "Don't Fragment" (DF) flag in the IPv6 Fragment Header. This means that no IPv6 packets are meant to be fragmented or assembled by routers (i.e. as if DF was always on). I understand there's this assumption in the IPv4 protocol that if a packet with no DF flag arrives, then a packet with no DF flag departs. But what if the forwarder is translating to IPv6? One thing that can happen is:

![Fig.1 - NAT64 with defrag](images/iptc-defrag.svg)

1. Node A (IPv4) sends fragmentable (DF off) fragments.
2. (defrag assembles fragments and) NAT64 translates the packet.
3. Packet doesn't fit the MTU, so router B sends back the ICMPv6 error "<a href="http://tools.ietf.org/html/rfc4443#section-3.2" target="_blank">Packet too big</a>".
4. NAT64 translates the error into the spiritually equivalent ICMPv4 error "<a href="http://tools.ietf.org/html/rfc792" target="_blank">fragmentation needed (and DF set)</a>".
5. Node A says "What are you talking about? DF WAS NOT SET!!!"
6. Perhaps Node A creates smaller fragments.
7. Node A again receives the ICMP error, since defrag is still assembling in the NAT64 step.
8. Keep trying, keep failing.

The problem exists here because NAT64 was _forced_ into Linux's infrastructure. Pure NAT64 as explained by RFC 6146 assumes no defrag module; fragments are supposed to be _correlated_, never _assembled_. The correct way to do it can be exemplified as follows:

![Fig.2 - NAT64 without defrag](images/iptc-nodefrag.svg)

1. Node A (IPv4) sends fragmentable (DF off) fragments.
2. The NAT64 translates each fragment separately.
3a. This time each fragment is not a behemoth, so the router forwards.
3b. Alternatively, the fragments are still too big so Node A retries with smaller fragments. This time the fragments fit and the router forwards. Or Node A surrenders, but at least it wasn't Jool's fault.

The fact that iptables depends on defrag pretty much means that Jool has to _replace_ iptables if it wants to be as reliable as it can be.

## The current status

Jool has handled fragmentation correctly since version 3.1.0, but you might still come up with a couple of questions:

### I haven't rmmoded iptables. Why does everything seem to work?

While Jool (or stateful NAT64 for that matter) is incompatible with iptables, Netfilter is versatile enough that you don't have to kill iptables in order to deploy Jool.

That is because Netfilter queues modules and has packets visit them in a developer-defined order. The order is normally something in the lines of defrag -> conntrack -> firewall/NAT. Jool currently hooks itself to the beginning of the line, so it _steals_ packets directed to its pools and the rest of the chain doesn't get to see them.

(You might think this _robbery_ is a hack, but preventing the packets from reaching defrag [is neither the only nor the main reason why we did it](quirk-thieve.html).)

Note that packets that aren't meant to be translated (i.e. not headed towards the pools) are _not_ stolen by Jool, which means you can benefit from having them visit iptables for purposes such as local firewalling.

### What if I want to filter translated packets?

Yes, we have this problem. iptables is your usual firewall, and if Jool prevents it from touching your packets, you can't filter them.

But you see, the RFC dictates that stateful NAT64 implementations are supposed to provide a way for you to define filtering rules. We just <a href="https://github.com/NICMx/NAT64/issues/41" target="_blank">haven't implemented them yet</a>.

While we're at it, you can work around it by placing a firewall adjacent to the NAT64 machine to do your filtering.

