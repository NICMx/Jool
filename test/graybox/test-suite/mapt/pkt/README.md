# Graybox Tests: Basic

Simplest possible translation tests for MAP-T Jool.

## aa

The client sends a TCP packet to the server.

	packet aat
		20	IPv4	src:192.0.2.8 dst:203.0.113.8
		20	TCP
		4	Payload

	packet aae1: aat, translated by the CE.
		40	IPv6	src:2001:db8:4464:8::c000:208:0 dst:64:ff9b::203.0.113.8 hopLimit:63
		20	TCP
		4	Payload

	packet aae2: aae1, translated by the BR.
		20	IPv4	src:192.0.2.8 dst:203.0.113.8 ttl:62 !df
		20	TCP
		4	Payload

Validations:

- Send `aat` on "client" namespace. "br" namespace must receive `aae1`.
- Send `aat` on "client" namespace. "server" namespace must receive `aae2`. 

## ab

The server sends a TCP packet to the client.

	packet abt
		20	IPv4	src:203.0.113.8 dst:192.0.2.8
		20	TCP
		4	Payload

	packet abe1: abt, translated by the CE.
		40	IPv6	src:64:ff9b::203.0.113.8 dst:2001:db8:4464:8::c000:208:0 hopLimit:63
		20	TCP
		4	Payload

	packet abe2: abe1, translated by the BR.
		20	IPv4	src:203.0.113.8 dst:192.0.2.8 ttl:62 !df
		20	TCP
		4	Payload

Validations:

- Send `abt` on "server" namespace. "ce" namespace must receive `abe1`.
- Send `abt` on "server" namespace. "client" namespace must receive `abe2`. 

## ac

Same as "aa," except UDP.

	packet act
		20	IPv4	src:192.0.2.8 dst:203.0.113.8
		8	UDP
		4	Payload

	packet ace1
		40	IPv6	src:2001:db8:4464:8::c000:208:0 dst:64:ff9b::203.0.113.8 hopLimit:63
		8	UDP
		4	Payload

	packet ace2
		20	IPv4	src:192.0.2.8 dst:203.0.113.8 ttl:62 !df
		8	UDP
		4	Payload

## ad

Same as "ab," except UDP.

	packet adt
		20	IPv4	src:203.0.113.8 dst:192.0.2.8
		20	TCP
		4	Payload

	packet ade1
		40	IPv6	src:64:ff9b::203.0.113.8 dst:2001:db8:4464:8::c000:208:0 hopLimit:63
		20	TCP
		4	Payload

	packet ade2
		20	IPv4	src:203.0.113.8 dst:192.0.2.8 ttl:62 !df
		20	TCP
		4	Payload

## ae

Same as "aa," except ICMP ping.

	packet aet
		20	IPv4	src:192.0.2.8 dst:203.0.113.8
		8	ICMPv4	type:8 code:0
		4	Payload

	packet aee1
		40	IPv6	src:2001:db8:4464:8::c000:208:0 dst:64:ff9b::203.0.113.8 hopLimit:63
		8	ICMPv6	type:128 code:0
		4	Payload

	packet aee2
		20	IPv4	src:192.0.2.8 dst:203.0.113.8 ttl:62 !df
		8	ICMPv4	type:8 code:0
		4	Payload

## af

Same as "ab," except ICMP ping.

	packet aft
		20	IPv4	src:203.0.113.8 dst:192.0.2.8
		8	ICMPv4	type:0 code:0
		4	Payload

	packet afe1
		40	IPv6	src:64:ff9b::203.0.113.8 dst:2001:db8:4464:8::c000:208:0 hopLimit:63
		8	ICMPv6	type:129 code:0
		4	Payload

	packet afe2
		20	IPv4	src:203.0.113.8 dst:192.0.2.8 ttl:62 !df
		8	ICMPv4	type:0 code:0
		4	Payload

## ag

Same as "aa," except ICMP error.

- Server sends 203.8 -> 192.8
- MAP-T midpoint: 64::203.8 -> 2001::192.8
- Client receives 203.8 -> 192.8
- Client responds 192.8 -> 203.8 containing 203.8 -> 192.8
- MAP-T midpoint: 2001::192.8 -> 64::203.8 containing 64::203.8 -> 2001::192.8


	packet agt
		20	IPv4	src:192.0.2.8 dst:203.0.113.8
		8	ICMPv4
		20	IPv4	src:203.0.113.8 dst:192.0.2.8 ttl:62
		20	TCP
		4	Payload

	packet age1
		40	IPv6	src:2001:db8:4464:8::c000:208:0 dst:64:ff9b::203.0.113.8 hopLimit:63
		8	ICMPv6
		40	IPv6	src:64:ff9b::203.0.113.8 dst:2001:db8:4464:8::c000:208:0 hopLimit:62
		20	TCP
		4	Payload

	packet age2
		20	IPv4	src:192.0.2.8 dst:203.0.113.8 ttl:62 !df
		20	ICMPv4
		20	IPv4	src:203.0.113.8 dst:192.0.2.8 ttl:62 !df
		20	TCP
		4	Payload

## ah

Same as "ab," except ICMP error.

	packet aht
		20	IPv4	src:203.0.113.8 dst:192.0.2.8
		20	ICMPv4
		20	IPv4	src:192.0.2.8 dst:203.0.113.8 ttl:62
		20	TCP
		4	Payload

	packet ahe1
		40	IPv6	src:64:ff9b::203.0.113.8 dst:2001:db8:4464:8::c000:208:0 hopLimit:63
		8	ICMPv6
		40	IPv6	src:2001:db8:4464:8::c000:208:0 dst:64:ff9b::203.0.113.8 hopLimit:62
		20	TCP
		4	Payload

	packet ahe2
		20	IPv4	src:203.0.113.8 dst:192.0.2.8 ttl:62 !df
		20	ICMPv4
		20	IPv4	src:192.0.2.8 dst:203.0.113.8 ttl:62 !df
		20	TCP
		4	Payload
