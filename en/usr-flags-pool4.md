---
language: en
layout: default
category: Documentation
title: --pool4
---

[Documentation](documentation.html) > [Userspace Application Arguments](documentation.html#userspace-application-arguments) > \--pool4

# \--pool4

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Arguments](#arguments)
   1. [Operations](#operations)
   2. [Options](#options)
4. [Examples](#examples)
5. [Notes](#notes)
6. [`--mark`](#mark)

## Description

Interacts with NAT64 Jool's [IPv4 transport address pool](pool4.html).

The IPv4 pool is the subset of the node's transport addresses which should be used to mask connections sourced from IPv6 nodes.

If pool4 is empty, Jool will try to mask packets using its own node's assigned IPv4 addresses, and their default unused port ranges. See [Notes](#notes).

## Syntax

	jool --pool4 (
		[--display] [--csv]
		| --count
		| --add <PROTOCOLS> <IPv4-prefix> <port-range> [--mark <mark>] [--force]
		| --remove <PROTOCOLS> <IPv4-prefix> <port-range> [--mark <mark>] [--quick]
		| --flush [--quick]
	)

	<PROTOCOLS> := [--tcp] [--udp] [--icmp]

## Arguments

### Operations

* `--display`: The pool's records are printed in standard output. This is the default operation.
* `--count`: Prints the number of tables, samples and transport addresses in standard output.
* `--add`: Uploads entries to the pool. See [notes](#notes).
* `--remove`: Deletes entries from the pool.
* `--flush`: Removes all entries from the pool.

### Options

| **Flag** | **Default** | **Description** |
| `--csv` | (absent) | Print the table in [_Comma/Character-Separated Values_ format](http://en.wikipedia.org/wiki/Comma-separated_values). This is intended to be redirected into a .csv file. |
| `--mark` | 0 | Packets carrying mark _n_ will only be translated using pool4 records with mark _n_. See [below](#mark). |
| `--tcp` | * | If present, the record being added or removed represents TCP transport addresses. |
| `--udp` | * | If present, the record being added or removed represents UDP transport addresses. |
| `--icmp` | * | If present, the record being added or removed represents "ICMP transport addresses" (Addresses and ICMP identifiers, not ports). |
| `<IPv4-prefix>` | - | Group of addresses you're adding or removing to/from the pool. The length defaults to 32, so you typically add and remove addresses instead of prefixes. |
| `<port-range>` | 1-65535 for TCP/UDP, 0-65535 for ICMP | Subset layer 4 identifiers (or ICMP ids) from the addresses which should be reserved for translation. |
| `--force` | (absent) | If present, add the elements to the pool even if they're too many.<br />(Will print a warning and quit otherwise.) |
| `--quick` | (absent) | If present, do not cascade removal to [BIB entries](bib.html).<br />`--quick` present is faster, `--quick` absent leaves a cleaner (and therefore more efficient) BIB database.<br />Leftover BIB entries will still be removed from the database and freed after they expire naturally.<br />See [this](usr-flags-quick.html) for a more verbose explanation. |

\* `--tcp`, `--udp` and `--icmp` are not mutually exclusive. If neither of them are present, the records are added or removed to/from all three protocols.

## Examples

Display the current addreses:

	$ jool --pool4 --display 
	  (empty)

Add several entries:

	# jool --pool4 --add 192.0.2.1
	$ jool --pool4 --display
	0	ICMP	192.0.2.1	0-65535
	0	UDP	192.0.2.1	1-65535
	0	TCP	192.0.2.1	1-65535
	  (Fetched 3 entries.)
	# jool --pool4 --add          --tcp 192.0.2.2 7000-7999
	# jool --pool4 --add --mark 1 --tcp 192.0.2.2 8000-8999
	# jool --pool4 --add          --tcp 192.0.2.4/31
	$ jool --pool4 --display
	0	ICMP	192.0.2.1	0-65535
	0	UDP	192.0.2.1	1-65535
	0	TCP	192.0.2.1	1-65535
	0	TCP	192.0.2.2	7000-7999
	0	TCP	192.0.2.4	1-65535
	0	TCP	192.0.2.5	1-65535
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

You need to be aware that your NAT64 machine needs to reserve transport addresses for translation purposes. If something within it tries to open a connection from transport address `192.0.2.1#5000` and at the same time a translation yields source transport address `192.0.2.1#5000`, evil things will happen.

In other words, you don't want pool4's domain to intersect with other port ranges (just like you don't want other port ranges intersecting with other port ranges).

You already know the ports owned by any servers parked in your NAT64, if any. The other one you need to keep in mind is the [ephemeral range](https://en.wikipedia.org/wiki/Ephemeral_port):

	$ sysctl net.ipv4.ip_local_port_range 
	net.ipv4.ip_local_port_range = 32768	61000

Linux's ephemeral port range defaults to 32768-61000. Therefore, Jool falls back to use ports 61001-65535 (of whatever primary global addresses its node is wearing) when pool4 is empty. You can change the former by tweaking sysctl `sys.net.ipv4.ip_local_port_range`, and the latter by means of `--pool4 --add` and `--pool4 --remove`.

Say your NAT64's machine has address 192.0.2.1 and pool4 is empty.

	$ jool --pool4 --display
	  (empty)

This means Jool is using ports and ICMP ids 61001-65535 of address 192.0.2.1. Let's add them explicitely:

	# jool --pool4 --add 192.0.2.1 61001-65535
	# jool --pool4 --display
	0	ICMP	192.0.2.1	61001-65535
	0	UDP	192.0.2.1	61001-65535
	0	TCP	192.0.2.1	61001-65535
	  (Fetched 3 samples.)

So, for example, if you only have this one address, but want to reserve more ports for translation, you have to substract them from elsewhere. The ephemeral range is a good candidate:

	# sysctl -w net.ipv4.ip_local_port_range="32768 40000"
	# jool --pool4 --add 192.0.2.1 40001-61000
	$ sysctl net.ipv4.ip_local_port_range 
	net.ipv4.ip_local_port_range = 32768	40000
	$ jool --pool4 --display
	0	ICMP	192.0.2.1	40001-65535
	0	UDP	192.0.2.1	40001-65535
	0	TCP	192.0.2.1	40001-65535
	  (Fetched 3 samples.)

> ![Warning](../images/warning.svg) Jool is incapable of ensuring pool4 does not intersect with other port ranges; this validation is the operator's responsibility.

## `--mark`

Mark allows you to assign different IPv4 transport address ranges to different IPv6 clients.

Pool4 entries carrying mark _n_ will only affect packets marked _n_. You can mark packets any way you want using standard iptables matching done in IPv6 prerouting.

For example:

![Fig. 1 - Mark diagram](../images/network/pool4-mark.svg)

	$ # Packets from network 2001:db8:1::/64 will be masked using ports 10000-19999.
	# jool --pool4 --add 192.0.2.1 10000-19999 --mark 10
	# ip6tables -t mangle -I PREROUTING -s 2001:db8:1::/64 -j MARK --set-mark 10
	$
	$ # Packets from network 2001:db8:2::/64 will be masked using ports 20000-29999.
	# jool --pool4 --add 192.0.2.1 20000-29999 --mark 20
	# ip6tables -t mangle -I PREROUTING -s 2001:db8:2::/64 -j MARK --set-mark 20

Recognizing or narrowing down the IPv6 clients behind IPv4 transport addresses helps you create [IPv4-based ACLs]({{ site.repository-url }}/issues/115) and preventing groups of clients from hogging up IPv4 transport addresses (therefore DOSing the NAT64 for other clients).

