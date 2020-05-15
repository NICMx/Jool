# NAT64 Network

This is the network used by all the current NAT64 Graybox tests.

At a low level, its translator is configured by `xlat/nat64.sh` and the clients by `client/nat64/setup.sh`.

At a high level, the network can be temporarily created by running

	./namespace-create.sh
	./network-create.sh nat64

and destroyed by

	./network-destroy.sh nat64
	./namespace-destroy.sh

## Diagram

	+----+
	| n6 |
	+----+
	  | ::5
	  |
	  | 2001:db8::/96
	  |
	  | ::1
	+----+
	| j  |
	+----+
	  | .1
	  |
	  | 192.0.2/24
	  |
	  | .5
	+----+
	| n4 |
	+----+

`n6` and `n4` are actually the same machine (ie. the current namespace). `j` is enclosed in the `joolns` namespace.

All tests are packet exchanges between `n6` and `n4`, or by `n6` and `n6`, via `j`.

## Configuration

	n6
		Addresses:
			2001:db8::5/96
		Routes:
			64:ff9b::/96 via j

	j
		Addresses:
			2001:db8::1/96
			192.0.2.2/24
		Routes:
			203.0.113.0/24 via n4
		pool6:
			64:ff9b::/96
		pool4:
			192.0.2.2 1-3000 (TCP, UDP, ICMP)
		BIB:
			192.0.2.2#2000  2001:db8::5#2000    (TCP, UDP)
			192.0.2.2#1     2001:db8::5#1       (ICMP)
			192.0.2.2#1000  2001:db8:1::5#1001  (UDP)
			192.0.2.2#1002  2001:db8::5#1003    (UDP) (commented out)

	n4
		Addresses:
			192.0.2.5/24
		Routes:
			-

## Quick Interactions

Easy ping from n6 to n4:

	ping6 64:ff9b::192.0.2.5

Netcat server in n4:

	nc -ls 192.0.2.5 1234

Netcat client from n6:

	nc 64:ff9b::192.0.2.5 1234
