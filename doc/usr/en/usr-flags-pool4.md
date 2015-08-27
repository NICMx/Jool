---
layout: documentation
title: Documentation - Flags > IPv4 Pool
---

[Documentation](doc-index.html) > [Userspace Application](doc-index.html#userspace-application) > [Flags](usr-flags.html) > \--pool4

# \--pool4

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Arguments](#arguments)
4. [Examples](#examples)
5. [Notes](#notes)

## Description

Interacts with NAT64 Jool's [IPv4 transport address pool](op-pool4.html).

The IPv4 pool is the subset of the node's transport addresses which should be used to mask connections sourced from IPv6 nodes.

## Syntax

	jool --pool4 [--display] [--csv]
	jool --pool4 --count
	jool --pool4 --add [--mark <mark>] [--tcp] [--udp] [--icmp] <IPv4 prefix> [<port range>] [--force]
	jool --pool4 --remove [--mark <mark>] [--tcp] [--udp] [--icmp] <IPv4 prefix> [<port range>] [--quick]
	jool --pool4 --flush [--quick]

## Arguments

Operations:

* `--display`: The pool's records are printed in standard output. This is the default operation.
* `--count`: Prints the number of tables, samples and transport addresses in standard output.
* `--add`: Uploads entries to the pool.
* `--remove`: Deletes entries from the pool.
* `--flush`: Removes all entries from the pool.

Others:

| Name | Default | Description |
| `--csv` | (absent) | If present, print the table in CSV format. |
| [`--mark`](https://github.com/NICMx/NAT64/issues/115) | 0 | Packets carrying mark _n_ will only be translated using pool4 records with mark _n_. |
| `--tcp` | * | If present, the record being added or removed represents TCP transport addresses. |
| `--udp` | * | If present, the record being added or removed represents UDP transport addresses. |
| `--icmp` | * | If present, the record being added or removed represents "ICMP transport addresses" (Addresses and ICMP identifiers, not ports). |
| `<IPv4 prefix>` | - | Group of addresses you're adding or removing to/from the pool. The length defaults to 32, so you typically add and remove addresses instead of prefixes. |
| `<port range>` | 60001-65535 | Subset layer 4 identifiers (or ICMP ids) from the addresses which should be reserved for translation. |
| `--force` | (absent) | If present, add the elements to the pool even if they're too many. |
| [`--quick`](usr-flags-quick.html) | (absent) | If present, do not cascade removal to BIB entries. |

\* `--tcp`, `--udp` and `--icmp` are not mutually exclusive. If neither of them are present, the records are added or removed to/from all three protocols.

## Examples

Display the current addreses:

	$ jool --pool4 --display 
	  (empty)

Add several entries:

	# jool --pool4 --add 192.0.2.1
	$ jool --pool4 --display
	0	ICMP	192.0.2.1	60001-65535
	0	UDP	192.0.2.1	60001-65535
	0	TCP	192.0.2.1	60001-65535
	  (Fetched 3 entries.)
	# jool --pool4 --add          --tcp 192.0.2.2 7000-7999
	# jool --pool4 --add --mark 1 --tcp 192.0.2.2 8000-8999
	# jool --pool4 --add          --tcp 192.0.2.4/31
	$ jool --pool4 --display
	0	ICMP	192.0.2.1	60001-65535
	0	UDP	192.0.2.1	60001-65535
	0	TCP	192.0.2.1	60001-65535
	0	TCP	192.0.2.2	7000-7999
	0	TCP	192.0.2.4	60001-65535
	0	TCP	192.0.2.5	60001-65535
	1	TCP	192.0.2.2	8000-8999
	  (Fetched 7 entries.)

Remove some entries:

	# jool --pool4 --remove --mark 0 192.0.2.0/24 0-65535
	$ jool --pool4 --display
	1	TCP	192.0.2.2	8000-8999
	  (Fetched 1 entries.)

Clear the table:

	# jool --pool4 --flush
	$ jool --pool4 --display
	  (empty)

## Notes

If something within your NAT64 machine binds itself to one of the ports reserved by pool4, Jool will interfere with its packets. Therefore, it is in your best interests that pool4 doesn't collide with other port ranges.

You already know the ports owned by any servers parked in your NAT64, if any. The other one you need to keep in mind is the [ephemeral range](https://en.wikipedia.org/wiki/Ephemeral_port):

	$ sysctl net.ipv4.ip_local_port_range 
	net.ipv4.ip_local_port_range = 32768	61000

If you want to assign more ports to Jool, you have to substract them from elsewhere. The ephemeral range is a good candidate:

	$ jool --pool4 --display
	0	192.0.2.1	60001-65535
	  (Fetched 1 entries.)
	# sysctl -w net.ipv4.ip_local_port_range="32768 40000"
	# jool --pool4 --add 192.0.2.1 40001-60000
	$ sysctl net.ipv4.ip_local_port_range 
	net.ipv4.ip_local_port_range = 32768	40000
	$ jool --pool4 --display
	0	192.0.2.1	40001-65535
	  (Fetched 1 entries.)

