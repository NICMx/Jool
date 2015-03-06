---
layout: documentation
title: Documentation - Flags > Error Addresses
---

[Documentation](doc-index.html) > [Userspace Application](doc-index.html#userspace-application) > [Flags](usr-flags.html) > \--errorAddresses

# \--errorAddresses

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Options](#options)
4. [Examples](#examples)

## Description

Interacts with Jool's [RFC 6791 pool](misc-rfc6791.html). The pool defines addresses for untranslatable sources in ICMP errors.

If this pool is empty, Jool will fall back to use its node's addresses for these cases.

## Syntax

	jool_siit --errorAddresses [--display]
	jool_siit --errorAddresses --count
	jool_siit --errorAddresses --add <IPv4 prefix>
	jool_siit --errorAddresses --remove <IPv4 prefix>
	jool_siit --errorAddresses --flush

By the way: The name `--errorAddresses` might look awkwardly long, and it doesn't have a single-chara version, but thanks to the ARGP framework, you can still shorten it. These are all synonyms:

- `--errorAddresses`
- `--errorAddress`
- `--errorAddr`
- `--error`
- `--err`

Unfortunately, this does not apply during the `modprobe`.

## Options

- `--display`: The pool’s prefixes are printed in standard output. This is the default operation.
- `--count`: The number of _addresses_ (not prefixes) in the pool is printed in standard output.  
For example, if all you have is a /24 prefix, expect "256" as output.
- `--add`: Uploads `<IPv4 prefix>` to the pool.
- `--remove`: Deletes prefix `<IPv4 prefix>` from the pool.
- `--flush`: Removes all prefixes from the pool.

## Examples

Display the current prefixes:

	$ jool_siit --errorAddresses --display
	192.0.2.0/24
	198.51.100.0/26
	203.0.113.16/28
	  (Fetched 3 prefixes.)

This means the source address of a normally untranslatable ICMP error is going to be any within the following ranges: 192.0.2.0-192.0.2.255, 198.51.100.0-198.51.100.64, or 203.0.113.16-203.0.113.31.

Display only the prefix count:

	$ jool_siit --errorAddresses --count
	336

(That's /24 + /26 + /28 = 256 + 64 + 16.)

Remove a prefix:

	$ jool_siit --errorAddresses --remove 192.0.2.0/24

Return it:

	$ jool_siit --errorAddresses --add 192.0.2.0/24

Destroy all prefixes. Jool will start using its host's addresses as source.

	$ jool_siit --errorAddresses --flush

