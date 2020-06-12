# Graybox Tests: manual

In contrast with the "auto" (pktgen) tests, the manual tests were generated manually. They are a bunch of packet exchanges improvised after the auto tests, but before Graybox became a more formal endeavor.

## 6791v64

Test of pool6791v4. It's missing an empty pool counterpart.

	packet 6791v64t
		40	IPv6	src:4000::1
		8	ICMPv6
		40	IPv6	swap
		8	UDP
		32	Payload

	packet 6791v64e
		20	IPv4	!df ttl-- swap src:203.0.113.8
		8	ICMPv4
		20	IPv4	!df
		8	UDP
		32	Payload

Source address is untranslatable, so it gets assigned the pool6791v4 entry.

## empty6791-64

This is a puzzling one. From the name it seems like another attempt to check pool6791v4 assignment (which would make it a duplicate of [`6791v64`](#6791v64)), but the original blueprint looked like this:

	packet e6791-64-sender-nofrag
		40	IPv6	src:2001:db8:2::
		8	ICMPv6	type:1 code:0
		40	IPv6	swap
		8	UDP
		4	Payload

	packet e6791-64-receiver-nofrag
		20	IPv4	src:198.51.100.1 dst:198.51.100.2 ttl--
		8	ICMPv4	type:3 code:1
		20	IPv4
		8	UDP
		4	Payload

The source address is translatable (and does not yield 198.51.100.1), which suggests the test was already obsolete by the time it was git'd. I suppose this isn't too strange because, for some reason, the test was never actually referenced in the run script; it's been dormant this whole time.

The packets don't feature any additional peculiarities, so I don't think there is a reason to retain them.

Deleted.

## 6791v66

This is an amalgamation between the complications of ICMP errors, the RFC 6791v4 pool and hairpinning. Each might already have dedicated tests, but an aggregated version is welcomed. This is the intended story:

Original packet:

	2001:db8:3::1 -> 2001:db8:01[10.0.0.[0].10]::

Translates into

	1.0.0.1 -> 10.0.0.10

Hairpin, therefore

	2001:db8:01[1.0.0.[0].1]:: -> 2001:db8:2::a

Random IPv6 router triggers ICMP error:

	Outer packet:
		2001:db8::5 -> 2001:db8:01[1.0.0.[0].1]::
	Internal packet:
		2001:db8:01[1.0.0.[0].1]:: -> 2001:db8:2::a

Translates into

	Outer packet:
		<pool6791v4> -> 1.0.0.1
	Internal packet:
		1.0.0.1 -> 10.0.0.10

Hairpin, therefore

	Outer packet:
		2001:db8:01[pool6791v4]:: -> 2001:db8:3::1
	Internal packet:
		2001:db8:3::1 -> 2001:db8:01[10.0.0.[0].10]::

So:

	packet 6791v66t
		40	IPv6		src:2001:db8::5 dst:2001:db8:101:0:1::
		8	ICMPv6		type:1 code:0
		40	IPv6		src:2001:db8:101:0:1:: dst:2001:db8:2::a
		8	UDP
		4	Payload

	packet 6791v66e
		40	IPv6		src:2001:db8:1cb:71:8:: dst:2001:db8:3::1 ttl--
		8	ICMPv6		type:1 code:0
		40	IPv6		src:2001:db8:3::1 dst:2001:db8:10a:0:a::
		8	UDP
		4	Payload
