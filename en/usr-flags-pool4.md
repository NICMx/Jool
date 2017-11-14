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
5. [Empty pool4](#empty-pool4)
6. [Argument Details](#argument-details)
	1. [`<port-range>`](#port-range)
	2. [`--max-iterations`](#--max-iterations)
	3. [`--quick`](#--quick)

## Description

Interacts with NAT64 Jool's [IPv4 transport address pool](pool4.html).

The IPv4 pool is the subset of the node's transport addresses which are reserved to mask IPv6 nodes.

## Syntax

	jool --pool4 (
		[--display] [--csv]
		| --add <PROTOCOLS> <IPv4-prefix> <port-range>
				[--mark <mark>]
				[--max-iterations <iterations>]
				[--force]
		| --update <PROTOCOLS> --mark <mark> --max-iterations <iterations>
		| --remove <PROTOCOLS> <IPv4-prefix> <port-range> [--mark <mark>] [--quick]
		| --flush [--quick]
	)

	<PROTOCOLS> := [--tcp] [--udp] [--icmp]

## Arguments

### Operations

* `--display`: The pool4 table is printed in standard output. This is the default operation.
* `--add`: Uploads entries to the pool.  
  (Sets are created indirectly as a result.)
* `--update`: Modifies the Max Iterations field of a set.
* `--remove`: Deletes the entries from the pool that match the given criteria.
* `--flush`: Removes all entries from the pool.

> ![Note!](../images/warning.svg) The `--count` operation is no longer available in `--pool4` mode!
> 
> The replacement can be found [here](https://github.com/NICMx/pool4-usage-analyzer).

### Options

| **Flag** | **Default** | **Description** |
| `--csv` | (absent) | Print the table in [_Comma/Character-Separated Values_ format](http://en.wikipedia.org/wiki/Comma-separated_values). This is intended to be redirected into a .csv file. |
| `--mark` | 0 | Specifies the Mark value of the entry being added, removed or updated.<br>The minimum value is zero, the maximum is 4294967295. |
| `--tcp` | * | Apply operation on TCP entries (that also match `<mark>`). |
| `--udp` | * | Apply operation on UDP entries (that also match `<mark>`). |
| `--icmp` | * | Apply operation on ICMP entries (that also match `<mark>`). |
| [`--max-iterations`](#--max-iterations) | null | Specifies the Max Iterations value of the set being modified. |
| `<IPv4-prefix>` | - | Group of addresses you are adding or removing to/from the pool. The length is optional and defaults to 32. |
| [`<port-range>`](#port-range) | 1-65535 for TCP/UDP, 0-65535 for ICMP | Ports from `<IPv4-prefix>` you're adding or removing to/from the pool. |
| `--force` | (absent) | If present, add the elements to the pool even if they're too many.<br />(Will print a warning and quit otherwise.) |
| [`--quick`](#--quick) | (absent) | Do not cascade removal to [BIB entries](bib.html). |

\* `--tcp`, `--udp` and `--icmp` are not mutually exclusive. If neither of them are present, the records are added or removed to/from all three protocols.

## Examples

Display the current table:

	$ jool --pool4 --display
	+------------+-------+--------------------+-----------------+----------+----------+
	|       Mark | Proto |     Max iterations |         Address | Port min | Port max |
	+------------+-------+--------------------+-----------------+----------+----------+
	  (empty)

Add several entries:

	# jool --pool4 --add --tcp 192.0.2.1 1000-2500
	# jool --pool4 --add --tcp 192.0.2.1 1500-3000
	$ jool --pool4 --display
	+------------+-------+--------------------+-----------------+----------+----------+
	|       Mark | Proto |     Max iterations |         Address | Port min | Port max |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          0 |   TCP |       1024 ( auto) |       192.0.2.1 |     1000 |     3000 |
	+------------+-------+--------------------+-----------------+----------+----------+
	  (Fetched 1 samples.)
	# jool --pool4 --add --mark 1 --tcp 192.0.2.1 1500-2500
	# jool --pool4 --add          --tcp 192.0.2.8/30
	# jool --pool4 --add          --udp 192.0.2.100         --max-iterations 5000
	$ jool --pool4 --display
	+------------+-------+--------------------+-----------------+----------+----------+
	|       Mark | Proto |     Max iterations |         Address | Port min | Port max |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          1 |   TCP |       1024 ( auto) |       192.0.2.1 |     1500 |     2500 |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          0 |   TCP |       2059 ( auto) |       192.0.2.1 |     1000 |     3000 |
	|            |       |                    |       192.0.2.8 |        1 |    65535 |
	|            |       |                    |       192.0.2.9 |        1 |    65535 |
	|            |       |                    |      192.0.2.10 |        1 |    65535 |
	|            |       |                    |      192.0.2.11 |        1 |    65535 |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          0 |   UDP |       5000 (fixed) |     192.0.2.100 |        1 |    65535 |
	+------------+-------+--------------------+-----------------+----------+----------+
	  (Fetched 7 samples.)

Remove some entries:

	# jool --pool4 --remove --mark 0 192.0.2.0/24 0-65535
	$ jool --pool4 --display
	+------------+-------+--------------------+-----------------+----------+----------+
	|       Mark | Proto |     Max iterations |         Address | Port min | Port max |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          1 |   TCP |       1024 ( auto) |       192.0.2.1 |     1500 |     2500 |
	+------------+-------+--------------------+-----------------+----------+----------+
	  (Fetched 1 samples.)

Update the iteration cap of the remaining set:

	# jool --pool4 --update --mark 1 --tcp --max-iterations 9999
	$ jool --pool4 --display
	+------------+-------+--------------------+-----------------+----------+----------+
	|       Mark | Proto |     Max iterations |         Address | Port min | Port max |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          1 |   TCP |       9999 (fixed) |       192.0.2.1 |     1500 |     2500 |
	+------------+-------+--------------------+-----------------+----------+----------+
	  (Fetched 1 samples.)

Clear the table:

	# jool --pool4 --flush
	$ jool --pool4 --display
	+------------+-------+--------------------+-----------------+----------+----------+
	|       Mark | Proto |     Max iterations |         Address | Port min | Port max |
	+------------+-------+--------------------+-----------------+----------+----------+
	  (empty)

## Empty pool4

You might notice that Jool manages to translate successfully even when pool4 is empty. This is because, for the sake of ease of basic use, an empty pool4 behaves differently from a populated pool4.

Empty pool4 defaults to use ports 61001-65535 of whatever universe-scoped IPv4 addresses the node's interfaces have.

So, for example, if you see this,

	$ ip addr
	2: eth0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast state UP group blah blah blah
	    link/ether 1c:1b:0d:62:7a:42 brd ff:ff:ff:ff:ff:ff
	    inet 192.0.2.1/24 brd 192.0.2.255 scope global dynamic eth0

	$ jool --pool4 --display
	+------------+-------+--------------------+-----------------+----------+----------+
	|       Mark | Proto |     Max iterations |         Address | Port min | Port max |
	+------------+-------+--------------------+-----------------+----------+----------+
	  (empty)

Then Jool is behaving as if pool4 were configured as follows:

	+------------+-------+--------------------+-----------------+----------+----------+
	|       Mark | Proto |     Max iterations |         Address | Port min | Port max |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          0 |   TCP |       1024 ( auto) |       192.0.2.1 |    61001 |    65535 |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          0 |   UDP |       1024 ( auto) |       192.0.2.1 |    61001 |    65535 |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          0 |  ICMP |       1024 ( auto) |       192.0.2.1 |    61001 |    65535 |
	+------------+-------+--------------------+-----------------+----------+----------+

These default values are reasonable until you need the NAT64 to service anything other than a small IPv6 client population (as you only get 4535 available masks per protocol).

The reason why empty pool4 uses such a reduced port range can be found in the next section.

## Argument details

### `<port-range>`

You need to be aware that your NAT64 machine needs to **reserve** transport addresses for translation purposes. This is no different than port reservation during socket binding; if an server reserves port 80, no other application should be able to bind anything else to port 80, because then the data streams would get mixed. Conversely, if some program in the NAT64 machine binds socket `192.0.2.1#5000`, and at the same time one of Jool's translations successfully extracts transport address `192.0.2.1#5000` from pool4, evil things will happen.

_Jool is incapable of ensuring pool4 does not intersect with other defined port ranges; this validation is the operator's responsibility._

You already know the ports owned by any servers parked in your NAT64, if any. The other one you need to keep in mind is the [ephemeral range](https://en.wikipedia.org/wiki/Ephemeral_port):

	$ sysctl net.ipv4.ip_local_port_range 
	net.ipv4.ip_local_port_range = 32768	61000

As you can see, Linux's ephemeral port range defaults to 32768-61000, and this is the reason why Jool falls back to use ports 61001-65535 (of whatever primary global addresses its node is wearing) when pool4 is empty. You can change the former by tweaking sysctl `sys.net.ipv4.ip_local_port_range`, and the latter by means of `--pool4 --add` and `--pool4 --remove`.

Say your NAT64's machine has address 192.0.2.1 and pool4 is empty.

	$ jool --pool4 --display
	  (empty)

This means Jool is using ports and ICMP ids 61001-65535 of address 192.0.2.1. Let's add them explicitely:

	# jool --pool4 --add 192.0.2.1 61001-65535

So, for example, if you only have this one address, but want to reserve more ports for translation, you have to subtract them from elsewhere. The ephemeral range is a good candidate:

	# sysctl -w net.ipv4.ip_local_port_range="32768 40000"
	# jool --pool4 --add 192.0.2.1 40001-61000
	$ sysctl net.ipv4.ip_local_port_range 
	net.ipv4.ip_local_port_range = 32768	40000
	$ jool --pool4 --display
	+------------+-------+--------------------+-----------------+----------+----------+
	|       Mark | Proto |     Max iterations |         Address | Port min | Port max |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          0 |   TCP |       1024 ( auto) |       192.0.2.1 |    40001 |    65535 |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          0 |   UDP |       1024 ( auto) |       192.0.2.1 |    40001 |    65535 |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          0 |  ICMP |       1024 ( auto) |       192.0.2.1 |    40001 |    65535 |
	+------------+-------+--------------------+-----------------+----------+----------+
	  (Fetched 3 samples.)

### `--max-iterations`

Max Iterations is explained [here](pool4.html#algorithm-performance).

Its default is a reasonable generic value that attempts to find a reasonable balance between packet drops and runtime performance. It is computed as follows:

- If the set has less than 128k transport addresses, Max Iterations defaults to 1024 (ie. `128k / 128`).
- If the set has something between 128k and 1024k transport addresses, Max Iterations defaults to `number of transport addresses / 128`.
- If the set has more than 1024k transport addresses, Max Iterations defaults to 8192 (ie. `1024k / 128`).

The rationale for all of this can be found in the [source code](https://github.com/NICMx/Jool/blob/16957569f134939d914d82489f23c7b33970bb3b/mod/stateful/pool4/db.c#L850).

To return a fixed Max Iterations to a default value, use the `auto` keyword:

	$ jool --pool4 --display
	+------------+-------+--------------------+-----------------+----------+----------+
	|       Mark | Proto |     Max iterations |         Address | Port min | Port max |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          0 |   TCP |       9999 (fixed) |       192.0.2.1 |        1 |    65535 |
	+------------+-------+--------------------+-----------------+----------+----------+
	  (Fetched 1 samples.)
	# jool --pool4 --update --tcp --max-iterations auto
	$ jool --pool4 --display
	+------------+-------+--------------------+-----------------+----------+----------+
	|       Mark | Proto |     Max iterations |         Address | Port min | Port max |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          0 |   TCP |       1024 ( auto) |       192.0.2.1 |        1 |    65535 |
	+------------+-------+--------------------+-----------------+----------+----------+
	  (Fetched 1 samples.)

On the other hand, you can use the keyword `infinity` to remove the iteration limit. This yields the same behavior as Jool 3.5.4 and below. (Careful with exhausted pool4s!)

	# jool --pool4 --update --tcp --max-iterations infinity
	$ jool --pool4 --display
	+------------+-------+--------------------+-----------------+----------+----------+
	|       Mark | Proto |     Max iterations |         Address | Port min | Port max |
	+------------+-------+--------------------+-----------------+----------+----------+
	|          0 |   TCP |   Infinity (fixed) |       192.0.2.1 |        1 |    65535 |
	+------------+-------+--------------------+-----------------+----------+----------+
	  (Fetched 1 samples.)

### `--quick`

If you `--remove` or `--flush` a pool4 entry, the BIB entries that match it become obsolete because the packets they serve are no longer going to be translated. This is because a pool4 match is a prerequisite for translation.

* When `--quick` is absent during a pool4 entry removal, Jool will also get rid of the now obsolete "slaves". This saves memory, keeps the database consistent and optimizes BIB entry lookup during packet translations. The removal operation itself, however, is slower.
* On the other hand, when you do issue `--quick`, Jool will only purge the pool4 entries, thereby "orphaning" its BIB entries. This can be useful if you know you have too many BIB entries and want the operation to succeed immediately, or more likely you plan to re-add the pool4 entry in the future. Doing so will enable the (still remaining) slaves again.

Orphaned slaves will remain inactive in the database, and will eventually kill themselves once their normal removal conditions are met (ie. once all their sessions expire).

