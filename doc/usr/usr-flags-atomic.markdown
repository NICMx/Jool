---
layout: documentation
title: Documentation - Flags > Atomic Fragments
---

[Documentation](doc-index.html) > [Userspace Application](doc-index.html#userspace-application) > [Flags](usr-flags.html) > [\--global](usr-flags-global.html) > Atomic Fragments

# Atomic Fragments

## Index

1. [Overview](#overview)
2. [Flags](#flags)
	1. [`--atomicFragments`](#atomicfragments)
	2. [`--setDF`](#setdf)
	3. [`--genFH`](#genfh)
	4. [`--genID`](#genid)
	5. [`--boostMTU`](#boostmtu)

## Overview

"Atomic fragments" are IPv6 packets which are not fragmented but still contain a (redundant) [Fragment Header](https://tools.ietf.org/html/rfc2460#section-4.5). They are a hack in the NAT64 specification that intends to leverage the difference between the IPv4 MTU (576) and the IPv6 MTU (1280).

Atomic fragments are known to have [security implications](https://tools.ietf.org/html/rfc6946) and there is [official ongoing effort to deprecate them](https://tools.ietf.org/html/draft-ietf-6man-deprecate-atomfrag-generation-00). Even RFC 6145 (ie. stateless NAT64's core document) warns about [issues regarding the hack](http://tools.ietf.org/html/rfc6145#section-6).

From Jool's perspective, there are also technical drawbacks to allowing atomic fragments. The Linux kernel is particularly lacking when it comes to recognizing redundant fragment headers, so if Jool is generating one, Linux might fragment the packet in a funny way:

![Figure 1 - what could possibly go wrong?]()

(Jool 3.2 and below used to avoid this by not deferring fragmentation to the kernel, but this introduced other-subtler issues.)

As a consequence, Jool 3.3's default configuration **disables** atomic fragments. You should most likely **never** change this. The options described later in this document all have to do with atomic fragments and are now considerered **deprecated**. In fact, we intend to wipe them out as soon as (and if) [draft-gont-6man-deprecate-atomfrag-generation](http://www.ietf.org/id/draft-gont-6man-deprecate-atomfrag-generation-01.txt) is upgraded to RFC status.

Let it be known that we fully condone the deprecation of atomic fragments.

## Flags

### `--atomicFragments`

- Name: Allow atomic fragments?
- Type: Boolean
- Default: OFF
- Modes: Both (Stateless and Stateful)
- Translation direction: Both (IPv4 to IPv6 and IPv6 to IPv4)

This is a short version of all the following flags.

This:

{% highlight bash %}
$(jool) --atomicFragments true
{% endhighlight %}

is the same as

{% highlight bash %}
$(jool) --setDF true
$(jool) --genFH true
$(jool) --genID false
$(jool) --boostMTU false
{% endhighlight %}

This is the default behaviour requested by [RFC 6145](http://tools.ietf.org/html/rfc6145), and the IETF is hopefully going to deprecate it in the future. It is _not_ Jool's default and we do _not_ recommend it.

Also this:

{% highlight bash %}
$(jool) --atomicFragments false
{% endhighlight %}

is the same as

{% highlight bash %}
$(jool) --setDF false
$(jool) --genFH false
$(jool) --genID true
$(jool) --boostMTU true
{% endhighlight %}

This is an alternate mode defined both by RFC 6145 and [draft-gont-6man-deprecate-atomfrag-generation](http://www.ietf.org/id/draft-gont-6man-deprecate-atomfrag-generation-01.txt). The latter mandates this behaviour and is Jool 3.3's default.

### `--setDF`

- Name: DF flag always on
- Type: Boolean
- Default: OFF
- Modes: Both (Stateless and Stateful)
- Translation direction: IPv6 to IPv4

The logic is best described in pseudocode form:

		If the incoming packet has a fragment header:
			the outgoing packet's DF flag will be false.
		otherwise:
			if --setDF is true
				the outgoing packet's DF flag will be true.
			otherwise:
				if outgoing packet's length > 1280
					the outgoing packet's DF flag will be true.
				otherwise:
					the outgoing packet's DF flag will be false.

<a href="http://tools.ietf.org/html/rfc6145#section-6" target="_blank">Section 6 of RFC 6145</a> describes the rationale.

### `--genFH`

- Name: Generate IPv6 Fragment Header
- Type: Boolean
- Default: OFF
- Modes: Both (Stateless and Stateful)
- Translation direction: IPv4 to IPv6

If this is ON, Jool will always generate an "IPv6 Fragment Header" if the incoming IPv4 Packet does not set the DF flag.

If this is OFF, then Jool will not generate the "IPv6 Fragment Header" whether the Flag of the incoming IPv4 Packet is set or not set, unless the incoming packet is a fragment, the "IPv6 Fragment Header" will be generated.

This is the flag that causes Linux to flip out when it needs to fragment. It's broken, so activate at your own risk.

### `--genID`

- Name: Generate IPv4 identification
- Type: Boolean
- Default: ON
- Modes: Both (Stateless and Stateful)
- Translation direction: IPv6 to IPv4

All IPv4 packets contain an Identification field. IPv6 packets only contain an Identification field if they have a Fragment header.

If the incoming IPv6 packet has a fragment header, the <a href="http://en.wikipedia.org/wiki/IPv4#Header" target="_blank">IPv4 header</a>'s Identification field is _always_ copied from the low-order bits of the IPv6 fragment header's Identification value.

Otherwise:

- If `--genID` is OFF, the IPv4 header's Identification fields are set to zero.
- If `--genID` is ON, the IPv4 headers' Identification fields are set randomly.

### `--boostMTU`

- Name: Decrease MTU failure rate
- Type: Boolean
- Default: ON
- Modes: Both (Stateless and Stateful)
- Translation direction: IPv4 to IPv6 (ICMP errors only)

When a packet is too big for a link's MTU, routers generate <a href="http://tools.ietf.org/html/rfc4443#section-3.2" target="_blank">Packet too Big</a> ICMP errors on IPv6 and <a href="http://tools.ietf.org/html/rfc792" target="_blank">Fragmentation Needed</a> ICMP errors on IPv4. These error types are roughly equivalent, so Jool translates _Packet too Bigs_ into _Fragmentation Neededs_ and vice-versa.

These ICMP errors are supposed to contain the offending MTU so the emitter can resize and resend its packets accordingly.

The minimum MTU for IPv6 is 1280. The minimum MTU for IPv4 is 68. Therefore, Jool can find itself wanting to report an illegal MTU while translating a _Fragmentation Needed_ (v4) into a _Packet too Big_ (v6).

- If `--boostMTU` is OFF, Jool will not attempt to fix MTU values of _Packet too Big_ ICMP errors when they are too small.
- If `--boostMTU` is ON and an incoming _Fragmentation Needed_ reports a MTU which is smaller than 1280, Jool will report a MTU of 1280.

<a href="http://tools.ietf.org/html/rfc6145#section-6" target="_blank">Section 6 of RFC 6145</a> describes the rationale.

