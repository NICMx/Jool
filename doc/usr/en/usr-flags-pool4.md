---
language: en
layout: default
category: Documentation
title: --pool4
---

[Documentation](documentation.html) > [Userspace Application](documentation.html#userspace-application) > [Flags](usr-flags.html) > \--pool4

# \--pool4

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Arguments](#arguments)
4. [Examples](#examples)
5. [Notes](#notes)
6. [`--mark`](#mark)

## Description

Interacts with NAT64 Jool's [IPv4 transport address pool](pool4.html).

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
* `--add`: Uploads entries to the pool. See [notes](#notes).
* `--remove`: Deletes entries from the pool.
* `--flush`: Removes all entries from the pool.

Others:

| Name | Default | Description |
| `--csv` | (absent) | If present, print the table in CSV format. |
| `--mark` | 0 | Packets carrying mark _n_ will only be translated using pool4 records with mark _n_. See [below](#mark). |
| `--tcp` | * | If present, the record being added or removed represents TCP transport addresses. |
| `--udp` | * | If present, the record being added or removed represents UDP transport addresses. |
| `--icmp` | * | If present, the record being added or removed represents "ICMP transport addresses" (Addresses and ICMP identifiers, not ports). |
| `<IPv4 prefix>` | - | Group of addresses you're adding or removing to/from the pool. The length defaults to 32, so you typically add and remove addresses instead of prefixes. |
| `<port range>` | 60001-65535 | Subset layer 4 identifiers (or ICMP ids) from the addresses which should be reserved for translation. |
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

You need to be aware that your NAT64 machine needs to reserve transport addresses for translation purposes. If something within it tries to open a connection from transport address `192.0.2.1#5000` and at the same time a translation yields source transport address `192.0.2.1#5000`, evil things will happen. [iptables's NAT also suffers from this quirk](https://github.com/NICMx/NAT64/wiki/issue67:-Linux's-MASQUERADING-does-not-care-about-the-source-natting-overriding-existing-connections.).

In other words, you don't want pool4's domain to intersect with other port ranges (just like you don't want other port ranges intersecting with other port ranges).

You already know the ports owned by any servers parked in your NAT64, if any. The other one you need to keep in mind is the [ephemeral range](https://en.wikipedia.org/wiki/Ephemeral_port):

	$ sysctl net.ipv4.ip_local_port_range 
	net.ipv4.ip_local_port_range = 32768	61000

Linux's ephemeral port range defaults to 32768-61000. Therefore, Jool's port range for any given address defaults to 61001-65535. You can change the former by tweaking sysctl `sys.net.ipv4.ip_local_port_range`, and the latter by means of `--pool4 --add` and `--pool4 --remove`.

So, for example, if you want to assign more ports to Jool, you have to substract them from elsewhere. The ephemeral range is a good candidate:

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

## `--mark`

Mark allows you to assign different IPv4 transport address ranges to different IPv6 clients.

Pool4 entries carrying mark _n_ will only affect packets marked _n_. You can mark packets any way you want using standard iptables matching done in IPv6 prerouting.

For example:

![TODO diagram](../images/network/pool4-mark.svg)

	$ # Packets from network 2001:db8:1::/64 will be masked using ports 10000-19999.
	$ jool --pool4 --add 192.0.2.1 10000-19999 --mark 10
	$ ip6tables -t mangle -I PREROUTING -s 2001:db8:1::/64 -j MARK --set-mark 10
	$
	$ # Packets from network 2001:db8:2::/64 will be masked using ports 20000-29999.
	$ jool --pool4 --add 192.0.2.1 20000-29999 --mark 20
	$ ip6tables -t mangle -I PREROUTING -s 2001:db8:2::/64 -j MARK --set-mark 20

Recognizing or narrowing down the IPv6 clients behind IPv4 transport addresses helps you create [IPv4-based ACLs](https://github.com/NICMx/NAT64/issues/115) and preventing groups of clients from hogging up IPv4 transport addresses (therefore DOSing the NAT64 for other clients).

