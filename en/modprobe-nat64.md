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
	1. [`--first-time`](#--first-time)
	1. [`pool6`](#pool6)
	2. [`pool4`](#pool4)
	3. [`disabled`](#disabled)
	4. [`no_instance`](#noinstance)

## Syntax

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Most Distros</span>
	<span class="distro-selector" onclick="showDistro(this);">OpenWRT</span>
</div>

<!-- Most Distros -->
{% highlight bash %}
# /sbin/modprobe [--first-time] jool \
		[pool6=<IPv6 prefix>] \
		[pool4=<IPv4 prefixes>] \
		[disabled] \
		[no_instance]
{% endhighlight %}

<!-- OpenWRT -->
{% highlight bash %}
# insmod jool \
		[pool6=<IPv6 prefix>] \
		[pool4=<IPv4 prefixes>] \
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
# /sbin/modprobe [--first-time] jool \
		pool6=64:ff9b::/96 \
		pool4="198.51.100.1, 203.0.113.0/28" \
		disabled
{% endhighlight %}

<!-- Most Distros -->
{% highlight bash %}
# insmod jool \
		pool6=64:ff9b::/96 \
		pool4="198.51.100.1, 203.0.113.0/28" \
		disabled
{% endhighlight %}

## Arguments

IPv4 prefix lengths default to 32 and IPv6 prefix lengths default to 128.

Comma-separated arguments can contain up to 5 entries. If you need more, use the userspace application counterpart.

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

The RFC 6052 translation prefix of the Jool instance. It defines the IPv6 representation of the addresses of the IPv4 nodes. See the [NAT64 introduction](intro-xlat.html#stateful-nat64).

If this is not present, Jool cannot translate. You can therefore use the default to pause translation, just like [`disabled`](#disabled).

The prefix length must be 32, 40, 48, 56, 64 or 96 as per RFC 6052.

### `pool4`

- Name: IPv4 Transport Address Pool
- Type: Comma-separated list of IPv4 addresses/prefixes
- Userspace Application Counterpart: [`--pool4`](usr-flags-pool4.html)
- Default: Port range 61001-65535 of whatever addresses the node has in its interfaces.

IPv4 addresses the instance can mask IPv6 nodes with. See [IPv4 Transport Address Pool](pool4.html) for details.

Any address you insert via `pool4` defaults to use mark zero and contain port range 1-65535 and ICMP identifiers 0-65535. You can't change this during the modprobe; the userspace application version of this argument is therefore recommended instead.

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

