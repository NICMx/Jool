---
layout: documentation
title: Documentation - Userspace Application
---

# [Doc](doc-index.html) > [Userspace App](doc-index.html#userspace-application) > [Flags](usr-flags.html) > \--general

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Examples](#examples)
4. [Keys](#keys)
   1. [\--dropAddr](#dropaddr)
   2. [\--dropInfo](#dropinfo)
   3. [\--dropTCP](#droptcp)
   4. [\--toUDP](#toudp)
   5. [\--toTCPest](#totcpest)
   6. [\--toTCPtrans](#totcptrans)
   7. [\--toICMP](#toicmp)
   8. [\--maxStoredPkts](#maxstoredpkts)
   9. [\--setTC](#settc)
   10. [\--setTOS](#settos)
   11. [\--TOS](#tos)
   12. [\--setDF](#setdf)
   13. [\--genID](#genid)
   14. [\--boostMTU](#boostmtu)
   15. [\--plateaus](#plateaus)
   16. [\--minMTU6](#minmtu6)
   17. [\--toFrag](#tofrag)

## Description

Controls several of Jool's internal variables.

* Issue an empty `--general` command to display the current values of all of Jool's options.
* Enter a key and a value to edit the key's variable.

`--general` is the default configuration mode, so you never actually need to input that one flag.

## Syntax

	jool [--general]
	jool [--general] <flag key> <new value>

## Examples

{% highlight bash %}
$ # Display the configuration values, keys and values.
$ jool --general
$ # Same thing, shorter version.
$ # BTW: This looks very simple, but it still requires Jool's kernel module to be active.
$ jool
$ # Turn "address dependent filtering" on.
$ # true, false, 1, 0, yes, no, on and off all count as valid booleans.
$ jool --general --dropAddr true
{% endhighlight %}

## Keys

The following flag keys are available:

### \--dropAddr

- Name: Address-dependent filtering
- Type: Boolean
- Default: OFF

Suppose _n6_ is talking with _n4a_ via the NAT64:

![Fig.1: Legal chat](images/usr-dropaddr-1.svg)

The relevant [BIB entry](misc-bib.html) is

| IPv6 transport address | IPv4 transport address | Protocol |
|------------------------|------------------------|----------|
| 2001:db8::1#10         | 192.0.2.1#10           | TCP      |

_n4b_ realizes the existence of _n6_'s service, perhaps because _n4a_ tells him about it:

![Fig.2: n4b finds about n6](images/usr-dropaddr-2.svg)

Then _n4b_ tries to chat _n6_ too:

![Fig.3: suspicious query](images/usr-dropaddr-3.svg)

Because the BIB entry exists, _J_ knows that _n4b_ means "2001:db8::1#10" when he says "192.0.2.1#10", so the packet can technically be translated. However, because of the session tables, _J_ can also tell that _n6_ hasn't been talking to _n4b_ in the past.

If `--dropAddr` is OFF, _J_ will allow _n4b_'s packet to pass. If `--dropAddr` is ON, _J_ will drop _n4b_'s packet and respond with a "Communication Administratively Prohibited" ICMP error. This effectively wrecks any IPv4-started communication attempts, even if there are BIB entries (static or otherwise).

* If you're using the NAT64 to publish a IPv6-only service to the IPv4 Internet, it makes sense for `--dropAddr` to be OFF. This is because clients are expected to find out about the IPv6 service on their own, and the server doesn't normally start packet streams.
* If you're using the NAT64 to allow IPv6 nodes to browse the IPv4 Internet, it makes sense for `--dropAddr` to be ON. This is because clients choose their ports at random; it is suspicious for random outsider nodes to guess these ports.

### \--dropInfo

- Name: Filtering of ICMPv6 info messages
- Type: Boolean
- Default: OFF

If you turn this on, pings (both requests and responses) will be blocked while being translated from ICMPv6 to ICMPv4.

For some reason, we're not supposed to block pings from ICMPv4 to ICMPv6, but since you need both a request and a response for a successful echo, the outcome seems to be the same.

This rule will not affect Error ICMP messages.

### \--dropTCP

- Name: Dropping externally initiated TCP connections
- Type: Boolean
- Default: OFF

Turn `--dropTCP` ON to wreck any attempts of IPv4 nodes to initiate TCP communication to IPv6 nodes.

Of course, this will not block IPv4 traffic if some IPv6 node first requested it.

### \--toUDP

- Name: UDP session lifetime
- Type: Integer (seconds)
- Default: 5 minutes

When a UDP session has been lying around inactive for this long, its entry will be removed from the database automatically.

When you change this value, the lifetimes of all already existing UDP sessions are updated.

### \--toTCPest

- Name: TCP established session lifetime
- Type: Integer (seconds)
- Default: 2 hours

When an established TCP connection has remained inactive for this long, its existence will be questioned. Jool will send a probe packet to one of the endpoints and kill the session if a response is not received before the `--toTCPtrans` timeout.

When you change this value, the lifetimes of all already existing established TCP sessions are updated.

### \--toTCPtrans

- Name: TCP transitory session lifetime
- Type: Integer (seconds)
- Default: 4 minutes

When a unhealthy TCP session has been lying around inactive for this long, its entry will be removed from the database automatically. A "unhealthy" session is one in which the TCP handshake has not yet been completed, it is being terminated by the endpoints, or is technically established but has remained inactive for `--toTCPest` time.

When you change this value, the lifetimes of all already existing transitory TCP sessions are updated.

### \--toICMP

- Name: ICMP session lifetime
- Type: Integer (seconds)
- Default: 1 minute

When a ICMP session has been lying around inactive for this long, its entry will be removed from the database automatically.

When you change this value, the lifetimes of all already existing ICMP sessions are updated.

### \--maxStoredPkts

- Name: Maximum number of stored packets
- Type: Integer
- Default: 10

When an external (IPv4) node first attempts to open a connection and there's no [BIB entry](misc-bib.html) for it, Jool normally answers with an Address Unreachable (type 3, code 1) ICMP error message, since it cannot know which IPv6 node the packet is heading.

In the case of TCP, the situation is a little more complicated because the IPv4 node might be attempting a <a href="https://github.com/NICMx/NAT64/issues/58#issuecomment-43537094" target="_blank">Simultaneous Open of TCP Connections</a>. To really know what's going on, Jool has to store the packet for 6 seconds.

`--maxStoredPkts` is the maximum amount of packets Jool will store at a time. The default means that you can have up to 10 "simultaneous" simultaneous opens; Jool will fall back to answer the ICMP error message on the eleventh one.

### \--setTC

- Name: Override IPv6 traffic class
- Type: Boolean
- Default: OFF
- Translation direction: IPv4 to IPv6

The <a href="http://en.wikipedia.org/wiki/IPv6_packet#Fixed_header" target="_blank">IPv6 header</a>'s Traffic Class field is very similar to <a href="http://en.wikipedia.org/wiki/IPv4#Header" target="_blank">IPv4</a>'s Type of Service (TOS).

If you leave this OFF, the TOS value will be copied directly to the Traffic Class field. If you turn this ON, Jool will always set Traffic Class as **zero** instead.

### \--setTOS

- Name: Override IPv4 type of service
- Type: Boolean
- Default: OFF
- Translation direction: IPv6 to IPv4

The <a href="http://en.wikipedia.org/wiki/IPv6_packet#Fixed_header" target="_blank">IPv6 header</a>'s Traffic Class field is very similar to <a href="http://en.wikipedia.org/wiki/IPv4#Header" target="_blank">IPv4</a>'s Type of Service (TOS).

If you leave this OFF, the Traffic Class value will be copied directly to the TOS field during IPv6-to-IPv4 translations. If you turn this ON, Jool will always set TOS as [`--TOS`](#tos) instead.

### \--TOS

- Name: IPv4 type of service
- Type: Integer
- Default: 0
- Translation direction: IPv6 to IPv4

Value to set the TOS value of the packets' IPv4 fields during IPv6-to-IPv4 translations. _This only applies when [`--setTOS`](#settos) is ON_.

### \--setDF

- Name: DF flag always on
- Type: Boolean
- Default: ON
- Translation direction: IPv6 to IPv4

If this is ON, Jool will always set the Don't Fragment flags (as 1).

If this is OFF, then Jool will set the DF flag only if the length of the IPv6 packet being translated is less or equal than 88 or higher than 1280 bytes. You do this to avoid black holes caused by ICMPv4 filtering or non-RFC2460-compatible IPv6 hosts.

### \--genFH

- Name: Generate IPv6 Fragment Header
- Type: Boolean
- Default: ON
- Translation direction: IPv4 to IPv6

If this is ON, Jool will always generate an "IPv6 Fragment Header" if the incoming IPv4 Packet does not set the DF flag.

If this is OFF, then Jool will not generate the "IPv6 Fragment Header" whether the Flag of the incoming IPv4 Packet is set or not set, unless the incoming packet is a fragment, the "IPv6 Fragment Header" will be generated.

### \--genID

- Name: Generate IPv4 identification
- Type: Boolean
- Default: OFF
- Translation direction: IPv6 to IPv4

All IPv4 packets contain an Identification field. IPv6 packets only contain an Identification field if they have a Fragment header.

If the incoming IPv6 packet has a fragment header, the <a href="http://en.wikipedia.org/wiki/IPv4#Header" target="_blank">IPv4 header</a>'s Identification field is _always_ copied from the low-order bits of the IPv6 fragment header's Identification value.

Otherwise:

- If `--genID` is OFF, the IPv4 header's Identification fields are set to zero.
- If `--genID` is ON, the IPv4 headers' Identification fields are set randomly.

### \--boostMTU

- Name: Decrease MTU failure rate
- Type: Boolean
- Default: ON
- Translation direction: IPv4 to IPv6 (ICMP errors only)

When a packet is too big for a link's MTU, routers generate <a href="http://tools.ietf.org/html/rfc4443#section-3.2" target="_blank">Packet too Big</a> ICMP errors on IPv6 and <a href="http://tools.ietf.org/html/rfc792" target="_blank">Fragmentation Needed</a> ICMP errors on IPv4. These error types are roughly equivalent, so Jool translates _Packet too Bigs_ into _Fragmentation Neededs_ and vice-versa.

These ICMP errors are supposed to contain the offending MTU so the emitter can resize and resend its packets accordingly.

The minimum MTU for IPv6 is 1280. The minimum MTU for IPv4 is 68. Therefore, Jool can find itself wanting to report an illegal MTU while translating a _Packet too Big_ into a _Fragmentation Needed_.

- If `--boostMTU` is OFF, Jool will not attempt to fix MTU values of _Packet too Big_ ICMP errors when they are too small.
- If `--boostMTU` is ON and an incoming _Fragmentation Needed_ reports a MTU which is smaller than 1280, Jool will report a MTU of 1280.

See <a href="http://tools.ietf.org/html/rfc6145#section-6" target="_blank">section 6 of RFC 6145</a> if you need the rationale.

### \--plateaus

- Name: MTU plateaus
- Type: List of Integers separated by commas (If you want whitespace, remember to quote).
- Default: "65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68"
- Translation direction: IPv4 to IPv6 (ICMP errors only)

When a packet should not be fragmented and doesn't fit into a link it's supposed to traverse, the troubled router is supposed to respond an error message indicating _Fragmentation Needed_. Ideally, this error message would contain the MTU of the link so the original emitter would be aware of the ideal packet size and avoid fragmentation. However, the original ICMPv4 specification does not require routers to include this data.

Backwards compatibility awards IPv4 emmiters strategies to fall back when they encounter such a situation, but IPv6 has always been designed with the field present in mind. Therefore, if Jool translates a zero-MTU ICMPv4 message into a zero-MTU ICMPv6 message, chaos *might* ensue (actual results will depend mainly on the IPv6 client's implementation).

To address this problem, when Jool finds itself attempting to translate a zero-MTU message, it will replace the MTU with the greatest plateau which is lower than the original packet's Total Length field. Admittedly, this might or might not be the correct MTU, but is a very educated guess. See [this example](usr-flags-plateaus.html) for more details. More in-depth information can be found in <a href="http://tools.ietf.org/html/rfc1191" target="_blank">RFC 1191</a>.

Note that if `--boostMTU` is activated, the MTU will still be 1280 even if the relevant plateau is less than 1280.

Also, you don't really need to sort the values as you input them.

### \--minMTU6

- Name: Minimum IPv6 MTU
- Type: Integer
- Default: 1280
- Translation direction: IPv4 to IPv6

All of your IPv6 networks have MTUs. You should set `--minMTU6` as the smallest of them.

IPv4 routers fragment, IPv6 routers don't fragment. If Jool receives a fragmentable IPv4 packet (Don't Fragment (DF) bit off), it has to make sure it's small enough to fit into any forthcoming IPv6 links (because the translation to IPv6 turns fragmentable packets into non-fragmentable packets). Otherwise, the smaller IPv6 hop will not let the packet through.

The way Jool "makes sure it's small enough" is by fragmenting the packet by itself. So, if a fragmentable IPv4 packet gets translated into a IPv6 packet whose length is higher than `--minMTU6`, Jool will fragment it prior to sending it.

So again, you want `--minMTU6` to be the smallest of your IPv6 MTUs so any of these formerly fragmentable packets will manage to fit into any IPv6 networks.

This value defaults to 1280 because all IPv6 networks are theoretically guaranteed to support at least 1280 bytes per packet. If all of your IPv6 networks have a higher MTU, you can raise `--minMTU6` to decrease chances of fragmentation.

- The penalty of `--minMTU6` being too small is performance; you get some unwanted fragmentation.
- The penalty of `--minMTU6` being too big is reliability; the IPv6 nodes which are behind networks with lesser MTUs will not be able to receive packets from IPv4 whose DF flag os off and which, once translated, are larger than `--minMTU6`.

IPv6 packets and unfragmentable IPv4 packets don't need any of this because they imply the emitter is the one minding MTUs and packet sizes (via <a href="http://en.wikipedia.org/wiki/Path_MTU_Discovery" target="_blank">Path MTU Discovery</a> or whatever).

### \--toFrag

- Name: Defragmentation Timeout
- Type: Integer (seconds)
- Default: 2

Time in seconds to keep a packet's fragments in memory while it's being reassembled.

Because the defragmenter is fairly bare bones, new fragments of the same packet do not update the packet's timeout, so every packet has **exactly** `--toFrag` seconds to be reassembled (and never more).

You want this value to be big enough that fragments will have enough time to arrive to Jool, but at the same time small enough that attackers won't exhaust your node's memory by sending bursts of incomplete packets.

> _Note_
> 
> The kernel's defragmenters have proven to be largely incompatible with NAT64. Because NAT64 requires _some_ level of fragment correlation, Jool has its own defragmenter. That's why this flag exists.
> 
> We believe that the best way to implement our missing feature (<a href="https://github.com/NICMx/NAT64/issues/41" target="_blank">Filtering Policies</a>) is to blend Jool with iptables. Unfortunately, it appears that iptables requires use of the kernel's defragmenters, so it looks like we're standing in the loser end of a checkmate.
> 
> We still haven't decided how to address the missing feature, which means that we might or might not have to discard Jool's defragmenter in the future. On top of that, `--toFrag` is fairly dumb. Even if we decide to keep Jool's defragmenter, we expect this flag to be replaced by more effective resource management.
> 
> Therefore, if you depend on `--toFrag`, brace yourself for modifications in the future.

