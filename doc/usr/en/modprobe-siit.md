---
language: en
layout: default
category: Documentation
title: Kernel Module Arguments
---

[Documentation](documentation.html) > [Kernel Module Arguments](documentation.html#kernel-module-arguments) > `jool_siit`

# SIIT Jool's Kernel Module Arguments

## Index

1. [Syntax](#syntax)
2. [Example](#example)
3. [Arguments](#arguments)
	1. [`pool6`](#pool6)
	2. [`blacklist`](#blacklist)
	3. [`pool6791`](#pool6791)
	4. [`disabled`](#disabled)

## Syntax

	# /sbin/modprobe jool_siit \
			[pool6=<IPv6 prefix>] \
			[blacklist=<IPv4 prefixes>] \
			[pool6791=<IPv4 prefixes>] \
			[disabled]

## Example

	# /sbin/modprobe jool_siit \
			pool6=64:ff9b::/96 \
			blacklist=192.0.2.0,192.0.2.1/32,192.0.2.4/30,192.0.2.16/28,192.0.2.64/26 \
			pool6791="203.0.113.0/24, 198.51.100.0/24" \
			disabled

## Arguments

IPv4 prefix lengths default to 32 and IPv6 prefix lengths default to 128.

Comma-separated arguments can contain up to 5 entries. If you need more, use the userspace application counterpart.

### `pool6`

- Name: IPv6 Pool
- Type: IPv6 prefix
- Userspace Application Counterpart: [`--pool6`](usr-flags-pool6.html)
- Default: -

The RFC 6052 translation prefix. It's the base prefix Jool will be appending and removing from the packets as described in the [stock SIIT introduction](intro-nat64.html#siit-traditional).

As per RFC 6052, the prefix length must be 32, 40, 48, 56, 64 or 96.

### `blacklist`

- Name: IPv4 prefix blacklist
- Type: Comma-separated list of IPv4 addresses/prefixes
- Userspace Application Counterpart: [`--blacklist`](usr-flags-blacklist.html)
- Default: None

IPv4 addresses to exclude from [`pool6`](#pool6)-based translation.

### `pool6791`

- Name: RFC 6791 pool
- Type: Comma-separated list of IPv4 addresses/prefixes
- Userspace Application Counterpart: [`--pool6791`](usr-flags-pool6791.html)
- Default: None

Addresses to source untranslatably-sourced ICMPv6 errors with. See the [RFC 6791 summary](rfc6791.html).

Defaults to the Jool machine's natural source IPv4 address.

### `disabled`

- Name: Insert Jool, but do not translate yet.
- Type: -
- Userspace Application Counterpart: [`--enable` and `--disable`](usr-flags-global.html#enable---disable)

Starts Jool inactive. If you're using the userspace application, you can use it to ensure you're done configuring before your traffic starts getting translated.

If not present, Jool starts translating traffic right away.

