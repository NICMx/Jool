---
layout: documentation
title: Documentation - Flags > IPv4 Pool
---

[Documentation](doc-index.html) > [Userspace Application](doc-index.html#userspace-application) > [Flags](usr-flags.html) > \--pool4

# \--pool4

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Options](#options)
   1. [Operations](#operations)
   2. [`--quick`](#quick)
4. [Examples](#examples)

## Description

Interacts with Jool's IPv4 pool.

the IPv4 pool is the subset of the node's address which should be used for translation.

Because the current implementation [leaves a lot to be desired](https://github.com/NICMx/NAT64/issues/117#issuecomment-66942415), editing the pool is very slow and memory-demanding. You want to avoid managing prefix lenghts of /24 and below in this case.

## Syntax

	jool --pool4 [--display]
	jool --pool4 --count
	jool --pool4 --add <IPv4 prefix>
	jool --pool4 --remove <IPv4 prefix> [--quick]
	jool --pool4 --flush [--quick]

## Options

### Operations

* `--display`: The pool's addresses are printed in standard output. This is the default operation.
* `--count`: The number of addresses in the pool is printed in standard output.
* `--add`: Uploads all of `<IPv4 prefix>`'s addresses to the pool.
* `--remove`: Deletes from the tables all of `<IPv4 prefix>`'s addresses.
* `--flush`: Removes all addresses from the pool.

`<IPv4 prefix>`'s length defaults to 32, so you can add and remove addresses instead of prefixes.

### \--quick

See [`--quick`](usr-flags-quick.html).

## Examples

Display the current addresses:

	$ jool --pool4 --display
	192.0.2.1/32
	198.51.100.1/32
	203.0.113.8/32
	  (Fetched 3 prefixes.)

Display only the address count:

	$ jool --pool4 --count
	3

Remove a couple of entries:

	# jool --pool4 --remove 192.0.2.1
	# jool --pool4 --remove 198.51.100.1

Return one entry:

	# jool --pool4 --add 192.0.2.1

