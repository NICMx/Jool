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
	1. [`--first-time`](#--first-time)
	1. [`pool6`](#pool6)
	2. [`blacklist`](#blacklist)
	3. [`pool6791`](#pool6791)
	4. [`disabled`](#disabled)
	5. [`no_instance`](#noinstance)

## Syntax

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Most Distros</span>
	<span class="distro-selector" onclick="showDistro(this);">OpenWRT</span>
</div>

<!-- Most Distros -->
{% highlight bash %}
# /sbin/modprobe [--first-time] jool_siit \
		[pool6=<IPv6 prefix>] \
		[blacklist=<IPv4 prefixes>] \
		[pool6791=<IPv4 prefixes>] \
		[disabled] \
		[no_instance]
{% endhighlight %}

<!-- OpenWRT -->
{% highlight bash %}
# insmod jool_siit \
		[pool6=<IPv6 prefix>] \
		[blacklist=<IPv4 prefixes>] \
		[pool6791=<IPv4 prefixes>] \
		[disabled] \
		[no_instance]
{% endhighlight %}

## Example

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Most Distros</span>
	<span class="distro-selector" onclick="showDistro(this);">OpenWRT</span>
</div>

<!-- Most Distros -->
{% highlight bash %}
# /sbin/modprobe [--first-time] jool_siit \
		pool6=64:ff9b::/96 \
		blacklist=192.0.2.0,192.0.2.1/32,192.0.2.4/30,192.0.2.16/28,192.0.2.64/26 \
		pool6791="203.0.113.0/24, 198.51.100.0/24" \
		disabled
{% endhighlight %}

<!-- OpenWRT -->
{% highlight bash %}
# insmod jool_siit \
		pool6=64:ff9b::/96 \
		blacklist=192.0.2.0,192.0.2.1/32,192.0.2.4/30,192.0.2.16/28,192.0.2.64/26 \
		pool6791="203.0.113.0/24, 198.51.100.0/24" \
		disabled
{% endhighlight %}

## Arguments

IPv4 prefix lengths default to 32 and IPv6 prefix lengths default to 128.

Comma-separated arguments can contain up to 5 entries. Please use the userspace application counterpart if you need more.

### `--first-time`

I'm only including this for the sake of clarification: `--first-time` is not a Jool flag; it's a `modprobe` flag.

From [`man modprobe`](https://linux.die.net/man/8/modprobe):

> Normally, **modprobe** will succeed (and do nothing) if told to insert a module which is already present or to remove a module which isn't present. This is ideal for simple scripts; however, more complicated scripts often want to know whether **modprobe** really did something: this option makes modprobe fail for that case.

Particularly when inserting modules, usage of this flag is strongly recommended; its absence tends to confuse users because of the silenced errors.

### `pool6`

- Name: IPv6 Pool
- Type: IPv6 prefix
- Userspace Application Counterpart: [`--pool6`](usr-flags-pool6.html)
- Default: -

The RFC 6052 translation prefix of the Jool instance being created. It is the base prefix Jool will be appending and removing from the packets as described in the [stock SIIT introduction](intro-xlat.html#siit-traditional).

The prefix length must be 32, 40, 48, 56, 64 or 96 as per RFC 6052.

### `blacklist`

- Name: IPv4 prefix blacklist
- Type: Comma-separated list of IPv4 addresses/prefixes
- Userspace Application Counterpart: [`--blacklist`](usr-flags-blacklist.html)
- Default: None

IPv4 addresses the Jool instance should exclude from [`pool6`](#pool6)-based translation.

### `pool6791`

- Name: RFC 6791 pool
- Type: Comma-separated list of IPv4 addresses/prefixes
- Userspace Application Counterpart: [`--pool6791`](usr-flags-pool6791.html)
- Default: None

Addresses the Jool instance can source untranslatably-sourced ICMPv6 errors with. See the [RFC 6791 summary](pool6791.html).

Defaults to the natural source IPv4 address of the namespace.

### `disabled`

- Name: Insert the Jool instance, but do not translate yet.
- Type: -
- Userspace Application Counterpart: [`--enable` and `--disable`](usr-flags-global.html#--enable---disable)

Hooks the Jool instance inactive. If you're using the userspace application, you can use it to ensure you're done configuring before your traffic starts getting translated.

If not present, the instance starts translating traffic right away.

### `no_instance`

- Name: Do not create a translator instance
- Type: -
- Userspace Application Counterpart: [`--instance --add`](usr-flags-instance.html)

Prevents the modprobe from hooking a translator instance on the current network namespace.

`no_instance` invalidates the rest of the arguments since all of them are intended to configure the default instance.

