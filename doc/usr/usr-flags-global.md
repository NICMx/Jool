---
layout: documentation
title: Documentation - Flags > Global
---

[Documentation](doc-index.html) > [Userspace Application](doc-index.html#userspace-application) > [Flags](usr-flags.html) > \--global

# \--global

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Examples](#examples)
4. [Keys](#keys)
	1. [`--enable`, `--disable`](#enable---disable)
	1. [`--dropAddr`](#dropaddr)
	2. [`--dropInfo`](#dropinfo)
	3. [`--dropTCP`](#droptcp)
	4. [`--toUDP`](#toudp)
	5. [`--toTCPest`](#totcpest)
	6. [`--toTCPtrans`](#totcptrans)
	7. [`--toICMP`](#toicmp)
	8. [`--maxStoredPkts`](#maxstoredpkts)
	9. [`--setTC`](#settc)
	10. [`--setTOS`](#settos)
	11. [`--TOS`](#tos)
	12. [`--atomicFragments`](#atomicfragments)
		1. [`--setDF`](#setdf)
		2. [`--genFH`](#genfh)
		3. [`--genID`](#genid)
		4. [`--boostMTU`](#boostmtu)
	13. [`--plateaus`](#plateaus)
	14. [`--minMTU6`](#minmtu6)

## Description

Controls several of Jool's internal variables.

* Issue an empty `--global` command to display the current values of all of Jool's options.
* Enter a key and a value to edit the key's variable.

`--global` is the default configuration mode, so you never actually need to input that one flag.

## Syntax

	jool_stateless [--global]
	jool_stateless [--global] <flag key> <new value>
	jool_stateful [--global]
	jool_stateful [--global] <flag key> <new value>

## Examples

Display the configuration values, keys and values:

{% highlight bash %}
$ jool_stateless --global
{% endhighlight %}

Same thing, shorter version:

{% highlight bash %}
$ # BTW: This looks very simple, but it still requires Jool's kernel module to be active.
$ jool_stateless
{% endhighlight %}

Turn "address dependent filtering" on:

{% highlight bash %}
$ # true, false, 1, 0, yes, no, on and off all count as valid booleans.
# jool_stateless --global --dropAddr true
{% endhighlight %}

## Keys

The following flag keys are available:

### `--enable`, `--disable`

- Name: Manual Enabling and Disabling
- Type: -
- Default: Depends on modprobe arguments
- Modes: Both (Stateless and Stateful)

Pauses and resumes packet translation. This might be useful if you want to change more than one configuration parameter at once and you don't want packets being translated inconsistently while you run the commands.

(If you don't want Jool to stop while you reconfigure, don't worry about this. Use it only if it feels right.)

Timeouts will _not_ be paused. In other words, [BIB](usr-flags-bib.html)/[session](usr-flags-session.html) entries and [stored packets](#maxstoredpkts) might die while Jool is idle.

### `--dropAddr`

- Name: Address-dependent filtering
- Type: Boolean
- Default: OFF
- Modes: Stateful only

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

### `--dropInfo`

- Name: Filtering of ICMPv6 info messages
- Type: Boolean
- Default: OFF
- Modes: Stateful only

If you turn this on, pings (both requests and responses) will be blocked while being translated from ICMPv6 to ICMPv4.

For some reason, we're not supposed to block pings from ICMPv4 to ICMPv6, but since you need both a request and a response for a successful echo, the outcome seems to be the same.

This rule will not affect Error ICMP messages.

### `--dropTCP`

- Name: Dropping externally initiated TCP connections
- Type: Boolean
- Default: OFF
- Modes: Stateful only

Turn `--dropTCP` ON to wreck any attempts of IPv4 nodes to initiate TCP communication to IPv6 nodes.

Of course, this will not block IPv4 traffic if some IPv6 node first requested it.

### `--toUDP`

- Name: UDP session lifetime
- Type: Integer (seconds)
- Default: 5 minutes
- Modes: Stateful only

When a UDP session has been lying around inactive for this long, its entry will be removed from the database automatically.

When you change this value, the lifetimes of all already existing UDP sessions are updated.

### `--toTCPest`

- Name: TCP established session lifetime
- Type: Integer (seconds)
- Default: 2 hours
- Modes: Stateful only

When an established TCP connection has remained inactive for this long, its existence will be questioned. Jool will send a probe packet to one of the endpoints and kill the session if a response is not received before the `--toTCPtrans` timeout.

When you change this value, the lifetimes of all already existing established TCP sessions are updated.

### `--toTCPtrans`

- Name: TCP transitory session lifetime
- Type: Integer (seconds)
- Default: 4 minutes
- Modes: Stateful only

When an unhealthy TCP session has been lying around inactive for this long, its entry will be removed from the database automatically. An "unhealthy" session is one in which the TCP handshake has not yet been completed, it is being terminated by the endpoints, or is technically established but has remained inactive for `--toTCPest` time.

When you change this value, the lifetimes of all already existing transitory TCP sessions are updated.

### `--toICMP`

- Name: ICMP session lifetime
- Type: Integer (seconds)
- Default: 1 minute
- Modes: Stateful only

When a ICMP session has been lying around inactive for this long, its entry will be removed from the database automatically.

When you change this value, the lifetimes of all already existing ICMP sessions are updated.

### `--maxStoredPkts`

- Name: Maximum number of stored packets
- Type: Integer
- Default: 10
- Modes: Stateful only

When an external (IPv4) node first attempts to open a connection and there's no [BIB entry](misc-bib.html) for it, Jool normally answers with an Address Unreachable (type 3, code 1) ICMP error message, since it cannot know which IPv6 node the packet is heading.

In the case of TCP, the situation is a little more complicated because the IPv4 node might be attempting a <a href="https://github.com/NICMx/NAT64/issues/58#issuecomment-43537094" target="_blank">Simultaneous Open of TCP Connections</a>. To really know what's going on, Jool has to store the packet for 6 seconds.

`--maxStoredPkts` is the maximum amount of packets Jool will store at a time. The default means that you can have up to 10 "simultaneous" simultaneous opens; Jool will fall back to answer the ICMP error message on the eleventh one.

### `--setTC`

- Name: Override IPv6 traffic class
- Type: Boolean
- Default: OFF
- Modes: Both (Stateless and Stateful)
- Translation direction: IPv4 to IPv6

The <a href="http://en.wikipedia.org/wiki/IPv6_packet#Fixed_header" target="_blank">IPv6 header</a>'s Traffic Class field is very similar to <a href="http://en.wikipedia.org/wiki/IPv4#Header" target="_blank">IPv4</a>'s Type of Service (TOS).

If you leave this OFF, the TOS value will be copied directly to the Traffic Class field. If you turn this ON, Jool will always set Traffic Class as **zero** instead.

### `--setTOS`

- Name: Override IPv4 type of service
- Type: Boolean
- Default: OFF
- Modes: Both (Stateless and Stateful)
- Translation direction: IPv6 to IPv4

The <a href="http://en.wikipedia.org/wiki/IPv6_packet#Fixed_header" target="_blank">IPv6 header</a>'s Traffic Class field is very similar to <a href="http://en.wikipedia.org/wiki/IPv4#Header" target="_blank">IPv4</a>'s Type of Service (TOS).

If you leave this OFF, the Traffic Class value will be copied directly to the TOS field during IPv6-to-IPv4 translations. If you turn this ON, Jool will always set TOS as [`--TOS`](#tos) instead.

### `--TOS`

- Name: IPv4 type of service
- Type: Integer
- Default: 0
- Modes: Both (Stateless and Stateful)
- Translation direction: IPv6 to IPv4

Value to set the TOS value of the packets' IPv4 fields during IPv6-to-IPv4 translations. _This only applies when [`--setTOS`](#settos) is ON_.

### `--atomicFragments`

See [Atomic Fragments](usr-flags-atomic.html).

### `--setDF`

See [Atomic Fragments](usr-flags-atomic.html).

### `--genFH`

See [Atomic Fragments](usr-flags-atomic.html).

### `--genID`

See [Atomic Fragments](usr-flags-atomic.html).

### `--boostMTU`

See [Atomic Fragments](usr-flags-atomic.html).

### `--plateaus`

- Name: MTU plateaus
- Type: List of Integers separated by commas (If you want whitespace, remember to quote).
- Default: "65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68"
- Modes: Both (Stateless and Stateful)
- Translation direction: IPv4 to IPv6 (ICMP errors only)

When a packet should not be fragmented and doesn't fit into a link it's supposed to traverse, the troubled router is supposed to respond an error message indicating _Fragmentation Needed_. Ideally, this error message would contain the MTU of the link so the original emitter would be aware of the ideal packet size and avoid fragmentation. However, the original ICMPv4 specification does not require routers to include this data.

Backwards compatibility awards IPv4 emmiters strategies to fall back when they encounter such a situation, but IPv6 has always been designed with the field present in mind. Therefore, if Jool translates a zero-MTU ICMPv4 message into a zero-MTU ICMPv6 message, chaos *might* ensue (actual results will depend mainly on the IPv6 client's implementation).

To address this problem, when Jool finds itself attempting to translate a zero-MTU message, it will replace the MTU with the greatest plateau which is lower than the original packet's Total Length field. Admittedly, this might or might not be the correct MTU, but is a very educated guess. See [this example](usr-flags-plateaus.html) for more details. More in-depth information can be found in <a href="http://tools.ietf.org/html/rfc1191" target="_blank">RFC 1191</a>.

Note that if `--boostMTU` is activated, the MTU will still be 1280 even if the relevant plateau is less than 1280.

Also, you don't really need to sort the values as you input them.

### `--minMTU6`

TODO this flag is obsolete but the idea is still absolutely vital - put it somewhere else.

- Name: Minimum IPv6 MTU
- Type: Integer
- Default: 1280
- Modes: Both (Stateless and Stateful)
- Translation direction: IPv4 to IPv6

All of your IPv6 networks have MTUs. You should set `--minMTU6` as the smallest of them.

IPv4 routers fragment, IPv6 routers don't fragment. If Jool receives a fragmentable IPv4 packet (Don't Fragment (DF) bit off), it has to make sure it's small enough to fit into any forthcoming IPv6 links (because the translation to IPv6 turns fragmentable packets into non-fragmentable packets). Otherwise, the smaller IPv6 hop will not let the packet through.

The way Jool "makes sure it's small enough" is by fragmenting the packet by itself. So, if a fragmentable IPv4 packet gets translated into a IPv6 packet whose length is higher than `--minMTU6`, Jool will fragment it prior to sending it.

So again, you want `--minMTU6` to be the smallest of your IPv6 MTUs so any of these formerly fragmentable packets will manage to fit into any IPv6 networks.

This value defaults to 1280 because all IPv6 networks are theoretically guaranteed to support at least 1280 bytes per packet. If all of your IPv6 networks have a higher MTU, you can raise `--minMTU6` to decrease chances of fragmentation.

- The penalty of `--minMTU6` being too small is performance; you get some unwanted fragmentation.
- The penalty of `--minMTU6` being too big is reliability; the IPv6 nodes which are behind networks with lesser MTUs will not be able to receive packets from IPv4 whose DF flag os off and which, once translated, are larger than `--minMTU6`.

IPv6 packets and unfragmentable IPv4 packets don't need any of this because they imply the emitter is the one minding MTUs and packet sizes (via <a href="http://en.wikipedia.org/wiki/Path_MTU_Discovery" target="_blank">Path MTU Discovery</a> or whatever).

