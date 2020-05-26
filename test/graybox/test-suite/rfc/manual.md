---
---

# Graybox Tests: manual

In contrast with the "auto" (pktgen) tests, the manual tests were generated manually. They are a bunch of packet exchanges improvised after the auto tests, but before Graybox became a more formal endeavor.

## SIIT Manual Tests

### 6791v64

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

### 6791v66

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

	packet 6791-66-t
		40	IPv6		src:2001:db8::5 dst:2001:db8:101:0:1::
		8	ICMPv6		type:1 code:0
		40	IPv6		src:2001:db8:101:0:1:: dst:2001:db8:2::a
		8	UDP
		4	Payload

	packet 6791-66-e
		40	IPv6		src:2001:db8:1cb:71:8:: dst:2001:db8:3::1 ttl--
		8	ICMPv6		type:1 code:0
		40	IPv6		src:2001:db8:3::1 dst:2001:db8:10a:0:a::
		8	UDP
		4	Payload

## NAT64 Manual Tests

### errors.ptb46

Sends a large IPv4 packet, expects Jool to generate a FN.

	packet ptb46-test
		20	IPv4
		8	UDP	dst:2000
		1233	Payload

	# BIB: 2001:db8::5#2000 192.0.2.2#2000

	packet ptb46-expected
		20	IPv4	!df swap
		8	ICMPv4	type:3 code:4 mtu:1260
		548	Payload	file:ptb46-test

That `!df` appears to stem from [this](https://elixir.bootlin.com/linux/v4.15/source/net/ipv4/ip_output.c#L1361) in combination with [this](https://elixir.bootlin.com/linux/v4.15/source/net/ipv4/icmp.c#L1222). It doesn't seem to be configurable for ICMP in particular, but I didn't look too hard.

### ptb.ptb46

Tests translation of a FN into a PTB.

	packet session
		40	IPv6	dst:64:ff9b::203.0.113.24
		8	UDP
		4	Payload

	# BIB: 2001:db8::5#2000 192.0.2.2#2000 (Static)
	# Session: 2001:db8::5#2000 64:ff9b::203.0.113.24#4000 192.0.2.2#2000 203.0.113.24#4000

	packet sender
		20	IPv4
		8	ICMPv4	type:3 code:4 mtu:1400
		20	IPv4	swap dst:203.0.113.24
		8	UDP
		4	Payload

	# Incoming tuple: 203.0.113.24#4000 -> 192.0.2.2#2000
	# Outgoing tuple: 64:ff9b::203.0.113.24#4000 -> 2001:db8::5#2000

	packet receiver
		40	IPv6	ttl-- swap
		8	ICMPv6	type:2 code:0 mtu:1420
		40	IPv6	dst:64:ff9b::203.0.113.24
		8	UDP
		4	Payload

### ptb.ptb64

Tests translation of a PTB into a FN.

	packet session
		40	IPv6	src:2001:db8:1::5
		8	UDP	src:1001
		4	Payload

	packet sender
		40	IPv6
		8	ICMPv6	type:2 code:0 mtu:1400
		40	IPv6	ttl-- swap dst:2001:db8:1::5
		8	UDP	swap dst:1001
		4	Payload

	packet receiver
		20	IPv4	!df ttl-- swap
		8	ICMPv4	type:3 code:4 mtu:1380
		20	IPv4	!df ttl--
		8	UDP	swap dst:1000
		4	Payload

I don't know why it uses a strange BIB.

### so.46

Sends a sessionless IPv4 TCP packet. Expects Jool to respond a Port Unreachable after 6 seconds.

	packet 46-sender
		20	IPv4
		20	TCP	src:50000 dst:1500
		4	Payload

	packet 46-receiver
		20	IPv4	!df swap
		8	ICMPv4
		44	Payload	file:46-sender


### so.success

Send an IPv4 TCP packet, wait 1 second, then send a matching IPv6 packet.

The IPv6 packet's translated counterpart should have a predictable source address and port despite not matching any existing BIB entries. (And the original IPv4 packet will be dropped silently, though we don't really have a way to test that through this framework.)

	packet success-receiver
		20	IPv4	!df ttl-- swap
		20	TCP	src:2600 dst:2601

	packet success-sender4
		20	IPv4
		20	TCP	src:2601 dst:2600

	packet success-sender6
		40	IPv6
		20	TCP	src:2600 dst:2601

This test fails if the session is already created. (eg. by running it twice.)

> TODO tests that create sessions should flush them by the end.
