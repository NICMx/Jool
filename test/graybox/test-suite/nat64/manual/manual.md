# Graybox Tests: manual

In contrast with the "auto" (pktgen) tests, the manual tests were generated manually. They are a bunch of packet exchanges improvised after the auto tests, but before Graybox became a more formal endeavor.

## misc.issue132

Sending a packet from N6 in hopes that N4 will bounce back an ICMP error due to nonexistant route 203.0.113. Mainly checks the address Jool uses to source the translated ICMP error behaves in accordance with #132's agreed upon rules. This test is the reason why N4 has v4 forwarding active (otherwise N4 drops the packet silently), and the translator has a bogus route to 200.0.113. (Though there might be other tests that exploit this configuration; I don't remember.)

2018-10-10: These tests appear to be affected by ICMP error rate-limits. It'd probably be a good idea to redesign them so N4 were not needed.

## errors.ptb46

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

## ptb.ptb46

Tests translation of a FN into a PTB.

	packet session-test
		40	IPv6	dst:64:ff9b::203.0.113.24
		8	UDP
		4	Payload

	# in tuple: 2001:db8::5#2000 -> 64:ff9b::203.0.113.24#4000
	# bib: 2001:db8::5#2000 | 192.0.2.2#2000 (static, from in tuple src)
	# session: 2001:db8::5#2000 | 64:ff9b::203.0.113.24#4000 | 192.0.2.2#2000 | 203.0.113.24#4000
	# out tuple: 192.0.2.2#2000 -> 203.0.113.24#4000 (bib.ipv4 -> RFC6052 destination)

	packet session-expected
		20	IPv4	src:192.0.2.2 dst:203.0.113.24 ttl-- !df
		8	UDP
		4	Payload

	packet test
		20	IPv4				# 192.5 -> 192.2
		8	ICMPv4	type:3 code:4 mtu:1400
		20	IPv4	swap dst:203.0.113.24	# 192.2 -> 203.24
		8	UDP				# 2000 -> 4000
		4	Payload

	# in tuple: 203.0.113.24#4000 -> 192.0.2.2#2000
	# bib: 2001:db8::5#2000 | 192.0.2.2#2000 (static, from in tuple dst)
	# session: 2001:db8::5#2000 | 64:ff9b::203.0.113.24#4000 | 192.0.2.2#2000 | 203.0.113.24#4000
	# out tuple: 64:ff9b::203.0.113.24#4000 -> 2001:db8::5#2000 (RFC6052'd source -> bib.ipv6)
	# out packet: 64:ff9b::203.0.113.24 -> 2001:db8::5 | 2001:db8::5#2000 -> 64:ff9b::203.0.113.24#4000 (outer is tuple, inner is tuple inverted.)

	packet expected
		40	IPv6	ttl-- swap			# 64:192.5 (overridden by issue 132) -> 2001:5
		8	ICMPv6	type:2 code:0 mtu:1420
		40	IPv6	dst:64:ff9b::203.0.113.24	# 2001:5 -> 64:203.24
		8	UDP					# 2000 -> 4000
		4	Payload

## ptb.ptb64

Tests translation of a PTB into a FN.

	packet session-test
		40	IPv6	src:2001:db8:1::5
		8	UDP	src:1001
		4	Payload

	# in tuple: 2001:db8:1::5#1001 -> 64:ff9b::192.0.2.5#4000
	# bib: 2001:db8:1::5#1001 | 192.0.2.2#1000 (static, from in tuple src)
	# session: 2001:db8:1::5#1001 | 64:ff9b::192.0.2.5#4000 | 192.0.2.2#1000 | 192.0.2.5#4000
	# out tuple: 192.0.2.2#1000 -> 192.0.2.5#4000 (bib.ipv4 -> RFC6052'd destination)

	packet session-expected
		20	IPv4	swap ttl-- !df
		8	UDP	src:1000
		4	Payload

	packet test
		40	IPv6
		8	ICMPv6	type:2 code:0 mtu:1400
		40	IPv6	ttl-- swap dst:2001:db8:1::5
		8	UDP	swap dst:1001
		4	Payload

	# in tuple: 2001:db8:1::5#1001 -> 64:ff9b::192.0.2.5#4000 (swapped inner addresses)
	# bib: 2001:db8:1::5#1001 | 192.0.2.2#1000 (static, from in tuple src)
	# session: 2001:db8:1::5#1001 | 64:ff9b::192.0.2.5#4000 | 192.0.2.2#1000 | 192.0.2.5#4000
	# out tuple: 192.0.2.2#1000 -> 192.0.2.5#4000 (bib.ipv4 -> RFC6052'd destination)
	# out packet: 192.0.2.2 -> 192.0.2.5 | 192.0.2.5#4000 -> 192.0.2.2#1000 (outer is tuple, inner is tuple inverted)

	packet expected
		20	IPv4	!df ttl-- swap
		8	ICMPv4	type:3 code:4 mtu:1380
		20	IPv4	!df ttl--
		8	UDP	swap dst:1000
		4	Payload

## ptb.ptb66

Test translation of a PTB into another PTB.

	packet session-test
		40	IPv6	dst:64:ff9b::c000:202
		8	UDP	src:1003 dst:1000
		4	Payload

	# First run:
	# - in tuple: 2001:db8::5#1003 -> 64:ff9b::c000:202#1000 (verbatim)
	# - bib: 2001:db8::5#1003 | 192.0.2.2#1002 (static, from in tuple src)
	# - session: 2001:db8::5#1003 | 64:ff9b::c000:202#1000 | 192.0.2.2#1002 | 192.0.2.2#1000
	# - out tuple: 192.0.2.2#1002 -> 192.0.2.2#1000 (bib.ipv4 -> RFC6052'd destination)
	# Hairpin:
	# - in tuple: 192.0.2.2#1002 -> 192.0.2.2#1000 (same as output tuple above)
	# - bib: 2001:db8:1::5#1001 | 192.0.2.2#1000 (static, from in tuple dst)
	# - session: 2001:db8:1::5#1001 | 64:ff9b::c000:202#1002 | 192.0.2.2#1000 | 192.0.2.2#1002
	# - out tuple: 64:ff9b::c000:202#1002 -> 2001:db8:1::5#1001 (RFC6052'd source -> bib.ipv6)

	packet session-expected
		40	IPv6	src:64:ff9b::c000:202 dst:2001:db8:1::5 ttl--
		8	UDP	src:1002 dst:1001
		4	Payload

	packet test
		40	IPv6	src:2001:db8::5 dst:64:ff9b::c000:202
		8	ICMPv6	type:2 code:0 mtu:1200
		40	IPv6	src:64:ff9b::c000:202 dst:2001:db8:1::5
		8	UDP	src:1002 dst:1001
		4	Payload

	# First run:
	# - in tuple: 2001:db8:1::5#1001 -> 64:ff9b::c000:202#1002 (swapped inner addresses)
	# - bib: 2001:db8:1::5#1001 | 192.0.2.2#1000 (static, from in tuple src)
	# - session: 2001:db8:1::5#1001 | 64:ff9b::c000:202#1002 | 192.0.2.2#1000 | 192.0.2.2#1002
	# - out tuple: 192.0.2.2#1000 -> 192.0.2.2#1002 (bib.ipv4 -> RFC6052'd destination)
	# - packet: 192.0.2.2 -> 192.0.2.2 | 192.0.2.2#1002 -> 192.0.2.2#1000 (outer is tuple, inner is tuple inverted)
	# Hairpin:
	# - in tuple: 192.0.2.2#1000 -> 192.0.2.2#1002 (same as out tuple above)
	# - bib: 2001:db8::5#1003 | 192.0.2.2#1002 (static, from in tuple dst)
	# - session: 2001:db8::5#1003 | 64:ff9b::c000:202#1000 | 192.0.2.2#1002 | 192.0.2.2#1000
	# - out tuple: 64:ff9b::c000:202#1000 -> 2001:db8::5#1003 (RFC6052'd source -> bib.ipv6)
	# - out packet: 64:ff9b::c000:202 -> 2001:db8::5 | 2001:db8::5#1003 -> 64:ff9b::c000:202#1000 (outer is tuple, inner is tuple inverted)

	packet expected
		40	IPv6	src:64:ff9b::c000:202 dst:2001:db8::5 ttl--
		8	ICMPv6	type:2 code:0 mtu:1280
		40	IPv6	src:2001:db8::5 dst:64:ff9b::c000:202
		8	UDP	src:1003 dst:1000
		4	Payload

## so.46

Sends a sessionless IPv4 TCP packet. Expects Jool to respond a Port Unreachable after 6 seconds.

	packet 46-sender
		20	IPv4
		20	TCP	src:50000 dst:1500
		4	Payload

	packet 46-receiver
		20	IPv4	!df swap
		8	ICMPv4
		44	Payload	file:46-sender

## so.66

Same as `so.46`, except hairpinning version.

	packet 66-sender
		40	IPv6	src:2001:db8::5 dst:64:ff9b::192.0.2.2
		20	TCP	src:50001 dst:1501
		4	Payload

	# First run: 
	# - in tuple: 2001:db8::5#50001 -> 64:ff9b::192.0.2.2#1501
	# - bib: 2001:db8::5#50001 | 192.0.2.2#x (dynamic)
	# - session: 64:ff9b::192.0.2.2#1501 | 192.0.2.2#1501
	# - out tuple: 192.0.2.2#x -> 192.0.2.2#1501 (bib.ipv4 -> 6052'd dst)
	# Hairpin:
	# - in tuple: 192.0.2.2#x -> 192.0.2.2#1501 (same as out tuple above)
	# - no bib

	packet 66-receiver
		40	IPv6	src:2001:db8::1 dst:2001:db8::5
		8	ICMPv6	type:1 code:4
		40	IPv6	src:2001:db8::5 dst:64:ff9b::192.0.2.2
		20	TCP	src:50001 dst:1501
		4	Payload

## so.success

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
