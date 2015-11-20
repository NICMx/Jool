---
language: en
layout: default
category: Documentation
title: Kernel Module Arguments
---

[Documentation](documentation.html) > [Kernel Module Arguments](documentation.html#kernel-module-arguments) > `jool`

# NAT64 Jool's Kernel Module Arguments

## Index

1. [Syntax](#syntax)
2. [Example](#example)
3. [Arguments](#arguments)
	1. [`pool6`](#pool6)
	2. [`pool4`](#pool4)
	3. [`disabled`](#disabled)

## Syntax

	# /sbin/modprobe jool \
			[pool6=<IPv6 prefix>] \
			[pool4=<IPv4 prefixes>] \
			[disabled]

## Example

	# /sbin/modprobe jool \
			pool6=64:ff9b::/96 \
			pool4="198.51.100.1, 203.0.113.0/28" \
			disabled

## Arguments

IPv4 prefix lengths default to 32 and IPv6 prefix lengths default to 128.

Comma-separated arguments can contain up to 5 entries. If you need more, use the userspace application counterpart.

### `pool6`

- Name: IPv6 Pool
- Type: IPv6 prefix
- Userspace Application Counterpart: [`--pool6`](usr-flags-pool6.html)
- Default: -

The RFC 6052 translation prefix. It defines the IPv6 representation of the addresses of the IPv4 nodes. See the [NAT64 introduction](intro-xlat.html#stateful-nat64).

If this is not present, Jool cannot translate. Therefore, you can use the default to pause translation, just like [`disabled`](#disabled).

As per RFC 6052, the prefix length must be 32, 40, 48, 56, 64 or 96.

### `pool4`

- Name: IPv4 Transport Address Pool
- Type: Comma-separated list of IPv4 addresses/prefixes
- Userspace Application Counterpart: [`--pool4`](usr-flags-pool4.html)
- Default: Port range 61001-65535 of whatever addresses the node has in its interfaces.

IPv4 addresses to mask IPv6 nodes with. See [IPv4 Transport Address Pool](pool4.html) for details.

Any address you insert via `pool4` defaults to use mark zero and contain port range 1-65535 and ICMP identifiers 0-65535. You can't change this during the modprobe; the userspace application version of this argument is therefore recommended.

### `disabled`

- Name: Insert Jool, but do not translate yet.
- Type: -
- Userspace Application Counterpart: [`--enable` and `--disable`](usr-flags-global.html#enable---disable)

Starts Jool inactive. If you're using the userspace application, you can use it to ensure you're done configuring before your traffic starts getting translated.

If not present, Jool starts translating traffic right away.

