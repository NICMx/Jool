# SIIT Network

This is the network used by all the current joolif Graybox tests.

It can be temporarily created by running

	./start-jool.sh ~/git/joolif

Improvise a test run with

	./test.sh ~/git/joolif/usr/joolif

To clean up:

	./end-jool.sh

## Diagram

	  |
	  | 2001:db8:3::/120
	  | 
	+----+
	| n6 |
	+----+
	  | 2001:db8:1c0:2:21:: (192.0.2.33)
	  |
	  | 2001:db8:1c0:2/64 (192.0.2/24 by pool6)
	  |
	  | 2001:db8:1c0:2:1:: (192.0.2.1)
	+--------+
	| siit0  |
	+--------+
	  | 198.51.100.1 (2001:db8:1c6:3364:1::)
	  |
	  | 198.51.100/24 (2001:db8:1c6:3364::/40 by pool6)
	  |
	  | 198.51.100.2 (2001:db8:1c6:3364:2::)
	+----+
	| n4 |
	+----+
	  |
	  | 10.0.0.0/24
	  |

`n6` and `n4` are actually the same namespace (the global namespace). `siit0` is the joolif interface.

All tests are packet exchanges between `n6` and `n4` via `siit0`. These packets sometimes reference nonexistent networks `2001:db8:3::/120` and `10.0.0.0/24`.

## Configuration

	n6
		Addresses:
			2001:db8:1c0:2:21::/64
		Routes:
			2001:db8:1c6:3364::/40 via j

	j
		Addresses:
			2001:db8:1c0:2:1::/64
			198.51.100.1/24
		Routes:
			2001:db8:3::/120 via n6 (Required by 7915.ga)
		pool6:
			2001:db8:100::/40
		EAMT:
			2001:db8:3::/120 1.0.0.0/24
			2001:db8:2::/120 10.0.0.0/24
		pool6791:
			203.0.113.8

	n4
		Addresses:
			198.51.100.2/24
		Routes:
			192.0.2.0/24 via j

## Quick Interactions

Easy ping from n6 to n4:

	ping6 2001:db8:1c6:3364:2::

Easy ping from n4 to n6:

	ping 192.0.2.33

Netcat server in n4:

	nc -ls 198.51.100.2 -p 1234

Netcat client from n6:

	nc 2001:db8:1c6:3364:2:: 1234
