---
language: en
layout: default
category: Documentation
title: --pool6791
---

[Documentation](documentation.html) > [Userspace Application Arguments](documentation.html#userspace-application-arguments) > \--pool6791

# \--pool6791

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Options](#options)
4. [Examples](#examples)

## Description

Interacts with Jool's [RFC 6791 pool](rfc6791.html). The pool defines addresses for untranslatable sources in ICMP errors.

If this pool is empty, Jool will fall back to use its node's addresses for these cases.

## Syntax

	jool_siit --pool6791 [--display]
	jool_siit --pool6791 --count
	jool_siit --pool6791 --add <IPv4 prefix>
	jool_siit --pool6791 --remove <IPv4 prefix>
	jool_siit --pool6791 --flush

## Options

- `--display`: The pool’s prefixes are printed in standard output. This is the default operation.
- `--count`: The number of _addresses_ (not prefixes) in the pool is printed in standard output.  
For example, if all you have is a /24 prefix, expect "256" as output.
- `--add`: Uploads `<IPv4 prefix>` to the pool.
- `--remove`: Deletes `<IPv4 prefix>` from the pool.
- `--flush`: Removes all prefixes from the pool.

## Examples

Display the current prefixes:

	$ jool_siit --pool6791 --display
	192.0.2.0/24
	198.51.100.0/26
	203.0.113.16/28
	  (Fetched 3 prefixes.)

This means the source address of a normally untranslatable ICMP error is going to be any within the following ranges: 192.0.2.0-192.0.2.255, 198.51.100.0-198.51.100.64, or 203.0.113.16-203.0.113.31.

Display only the prefix count:

	$ jool_siit --pool6791 --count
	336

(That's /24 + /26 + /28 = 256 + 64 + 16.)

Remove a prefix:

	$ jool_siit --pool6791 --remove 192.0.2.0/24

Return it:

	$ jool_siit --pool6791 --add 192.0.2.0/24

Destroy all prefixes. Jool will start using its host's addresses as source.

	$ jool_siit --pool6791 --flush

