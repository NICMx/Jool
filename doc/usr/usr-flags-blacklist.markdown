---
layout: documentation
title: Documentation - Flags > IPv4 Pool
---

[Documentation](doc-index.html) > [Userspace Application](doc-index.html#userspace-application) > [Flags](usr-flags.html) > \--blacklist

# \--blacklist

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Options](#options)
4. [Examples](#examples)

## Description

Interacts with Jool's blacklisted addresses pool.

The pool dictates which addresses can be translated using the [pool6](usr-flags-pool6.html) prefix. Notice [EAM](usr-flags-eamt.html) has more priority than the prefix, so you don't have to add an entry to this pool for every EAM entry you need.

There are some addresses Jool will refuse to translate, regardless of `blacklist`. These include

- The addresses that belong to Jool's node (because Jool can only be used in a forwarding fashion, currently).
- Software addresses (0.0.0.0/8).
- Host addresses (127.0.0.0/8).
- Link-local addresses (169.254.0.0/16).
- Multicast addresses (224.0.0.0/4).
- Limited broadcast (255.255.255.255/32).

## Syntax

	jool_siit --blacklist [--display]
	jool_siit --blacklist --count
	jool_siit --blacklist --add <IPv4 prefix>
	jool_siit --blacklist --remove <IPv4 prefix>
	jool_siit --blacklist --flush

## Options

* `--display`: The pool's addresses/prefixes are printed in standard output. This is the default operation.
* `--count`: The number of _addresses_ (not prefixes) in the pool is printed in standard output.  
For example, if all you have is a /30 prefix, expect "4" as output.
* `--add`: Uploads `<IPv4 prefix>` to the pool.
* `--remove`: Deletes from the tables the address `<IPv4 prefix>`.
* `--flush`: Removes all addresses/prefixes from the pool.

## Examples

Display the current addresses:

	$ jool_siit --blacklist --display
	192.0.2.0/28
	198.51.100.0/30
	203.0.113.8/32
	  (Fetched 3 prefixes.)

Display only the address count:

	$ jool_siit --blacklist --count
	21

(That's /28 + /30 + /32 = 16 + 4 + 1)

Remove a couple of entries:

	# jool_siit --blacklist --remove 192.0.2.0/28
	# jool_siit --blacklist --remove 198.51.100.0/30

Return one entry:

	# jool_siit --blacklist --add 192.0.2.0/28

