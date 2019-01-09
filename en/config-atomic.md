---
language: en
layout: default
category: Documentation
title: Atomic Configuration
---

[Documentation](documentation.html) > [Other Configuration](documentation.html#other-configuration) > Atomic Configuration

# Atomic Configuration

## Index

1. [Introduction](#introduction)
2. [Syntax](#syntax)
2. [Semantics](#semantics)
4. [Examples](#examples)
	1. [SIIT](#siit)
	2. [NAT64](#nat64)
6. [Changes from Jool 3](#changes-from-jool-3)

## Introduction

"Atomic Configuration" is a means to set up more than one of Jool's parameters at once (using a single `jool`/`jool_siit` call). Either all or none of the new configuration will be applied, so you don't have to worry about rolling back.

You can also think of it as "file configuration mode," since [JSON](https://www.json.org/) files are the means through which Atomic Configuration is retrieved.

## Syntax

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">SIIT</span>
	<span class="distro-selector" onclick="showDistro(this);">NAT64</span>
</div>

<!-- SIIT -->
{% highlight bash %}
jool_siit [-i <instance name>] file handle <path to json file> [--force]
{% endhighlight %}

<!-- NAT64 -->
{% highlight bash %}
jool      [-i <instance name>] file handle <path to json file> [--force]
{% endhighlight %}

`--force` silences warnings. (If you don't silence them, sometimes they will cause operation abortion; eg. [overlapping EAM entries](usr-flags-eamt.html#overlapping-eam-entries).)

## Semantics

The file describes one Jool instance. If the instance does not exist, it will be created. If it does exist, it will be updated. It will be an ordinary instance; you can subsequently apply any non-atomic operations on it, and delete it using [`instance remove`](usr-flags-instance.html) as usual.

Most of the options are the same as their userspace client counterparts, so see [Examples](#examples) for a couple of full JSON files with embedded links to the relevant client documentation.

On the top level, the mandatory fields are the instance name (either through the `-i` client argument or the `instance` JSON tag) and the `framework` tag (which must be set to either [`netfilter`](intro-jool.html#netfilter) or [`iptables`](intro-jool.html#iptables)).

Aside from vital fields from individual entries, everything else is optional, and will be initialized (or reinitialized) to **default values** ([NOT "old" values!](#changes-from-jool-3)) on omission.

Unrecognized tags will trigger errors, but any amount of `comment`s are allowed (and ignored) on all object contexts.

## Examples

### SIIT

<pre><code>{
	"comment": "Sample full SIIT configuration.",

	"instance": "instance name",
	"framework": "netfilter",

	"global": {
		"comment": "pool6 and the RFC6791v4 pool belong here, ever since Jool 4.",
		"<a href="usr-flags-global.html#pool6">pool6</a>": "64:ff9b::/96",
		"<a href="usr-flags-global.html#enable---disable">manually-enabled</a>": false,
		"<a href="usr-flags-global.html#zeroize-traffic-class">zeroize-traffic-class</a>": true,
		"<a href="usr-flags-global.html#override-tos">override-tos</a>": false,
		"<a href="usr-flags-global.html#tos">tos</a>": 254,
		"<a href="usr-flags-global.html#mtu-plateaus">mtu-plateaus</a>": [1, 2, 3, 4, 5, 6],
		"<a href="usr-flags-global.html#amend-udp-checksum-zero">amend-udp-checksum-zero</a>": true,
		"<a href="usr-flags-global.html#eam-hairpin-mode">eam-hairpin-mode</a>": "simple",
		"<a href="usr-flags-global.html#randomize-rfc6791-addresses">randomize-rfc6791-addresses</a>": false,
		"<a href="usr-flags-global.html#rfc6791v6-prefix">rfc6791v6-prefix</a>": null,
		"<a href="usr-flags-global.html#rfc6791v4-prefix">rfc6791v4-prefix</a>": null
	},

	"<a href="usr-flags-eamt.html">eamt</a>": [
		{
			"comment": {
				"text": "Here's a compound comment; the type is not checked.",
				"date": "2019-01-06"
			},
			"ipv6 prefix": "2001:db8:1::/128",
			"ipv4 prefix": "192.0.2.0"
		}, {
			"ipv6 prefix": "2001:db8:2::",
			"ipv4 prefix": "192.0.2.1/32"
		}, {
			"ipv6 prefix": "2001:db8:3::/124",
			"ipv4 prefix": "192.0.2.16/28"
		}
	],

	"comment": "This comment is relevant to blacklist4 maybe.",
	"<a href="usr-flags-blacklist.html">blacklist4</a>": [
		"198.51.100.0",
		"198.51.100.2/32",
		"198.51.100.32/27"
	]
}</code></pre>

Conceptually, updating an SIIT instance through atomic configuration is the same as dropping it and creating it anew. In practice, the former prevents the small window of time in which no translator exists.

### NAT64

There is one major caveat here: The current implementation of BIB/session is [not suitable to guarantee the atomicity of simultaneous modifications to a running database](https://github.com/NICMx/Jool/blob/v3.5.0/usr/common/target/json.c#L715). Therefore, **the `bib` tag below is only handled if the JSON file is being used to create a new instance. It will be silently ignored on updates**.

Sorry. This does not necessarily mean that atomic updating of static BIB entries will never be implemented, but there are no plans for now.

Also, `pool6` is mandatory and immutable (as normal). It must be set during instance creation and retain the same value on subsequent updates.

<pre><code>{
	"comment": "Sample full NAT64 configuration.",

	"instance": "instance name",
	"framework": "netfilter",

	"global": {
		"<a href="usr-flags-pool6.html">pool6</a>": "64:ff9b::/96",

		"<a href="usr-flags-global.html#--enable---disable">manually-enabled</a>": false,

		"<a href="usr-flags-global.html#--zeroize-traffic-class">zeroize-traffic-class</a>": true,
		"<a href="usr-flags-global.html#--override-tos">override-tos</a>": false,
		"<a href="usr-flags-global.html#--tos">tos</a>": 254,
		"<a href="usr-flags-global.html#--mtu-plateaus">mtu-plateaus</a>": [1, 2, 3, 4, 5, 6],
		"<a href="usr-flags-global.html#--maximum-simultaneous-opens">maximum-simultaneous-opens</a>": 16,
		"<a href="usr-flags-global.html#--source-icmpv6-errors-better">source-icmpv6-errors-better</a>": true,
		"<a href="usr-flags-global.html#--handle-rst-during-fin-rcv">handle-rst-during-fin-rcv</a>": true,
		"<a href="usr-flags-global.html#--f-args">f-args</a>": 10,

		"<a href="usr-flags-global.html#--logging-bib">logging-bib</a>": true,
		"<a href="usr-flags-global.html#--logging-session">logging-session</a>": true,

		"<a href="usr-flags-global.html#--address-dependent-filtering">address-dependent-filtering</a>": true,
		"<a href="usr-flags-global.html#--drop-icmpv6-info">drop-icmpv6-info</a>": true,
		"<a href="usr-flags-global.html#--drop-externally-initiated-tcp">drop-externally-initiated-tcp</a>": true,

		"<a href="usr-flags-global.html#--udp-timeout">udp-timeout</a>": "1:00:00",
		"<a href="usr-flags-global.html#--tcp-est-timeout">tcp-est-timeout</a>": "10:00:00",
		"<a href="usr-flags-global.html#--tcp-trans-timeout">tcp-trans-timeout</a>": "5:00",
		"<a href="usr-flags-global.html#--icmp-timeout">icmp-timeout</a>": "5:30",

		"<a href="usr-flags-global.html#--ss-enabled">ss-enabled</a>": true,
		"<a href="usr-flags-global.html#--ss-flush-asap">ss-flush-asap</a>": false,
		"<a href="usr-flags-global.html#--ss-flush-deadline">ss-flush-deadline</a>": 1000,
		"<a href="usr-flags-global.html#--ss-capacity">ss-capacity</a>": 256,
		"<a href="usr-flags-global.html#--ss-max-payload">ss-max-payload</a>": 600
	},

	"<a href="usr-flags-pool4.html">pool4</a>": [
		{
			"mark": 1,
			"protocol": "UDP",
			"prefix": "192.0.2.1",
			"port range": "61001-62000"
		}, {
			"mark": 1,
			"protocol": "ICMP",
			"prefix": "192.0.2.1/32",
			"port range": "1000-2000"
		}, {
			"protocol": "TCP",
			"prefix": "192.0.2.2/31"
		}
	],
	
	"<a href="usr-flags-bib.html">bib</a>": [
		{
			"protocol": "TCP",
			"ipv6 address": "2001:db8::1#80",
			"ipv4 address": "192.0.2.2#80"
		}, {
			"protocol": "UDP",
			"ipv6 address": "2001:db8::2#10000",
			"ipv4 address": "192.0.2.1#61500"
		}, {
			"protocol": "ICMP",
			"ipv6 address": "2001:db8:AAAA::1#44",
			"ipv4 address": "192.0.2.1#1044"
		}
	]
}</code></pre>

Updating a NAT64 instance through atomic configuration is not the same as dropping the instance and then creating another one in its place. Aside from skipping the translatorless time window through the former, you get to keep the BIB/session database.

## Changes from Jool 3

1. `pool6` and the RFC 6791 IPv4 pool were moved to the `global` object. (They used to be in the root.)
2. On NAT64, `pool6` is immutable now.
3. Added `instance` (the instance name) and `framework` (`netfilter` or `iptables`).
2. Comment tags are now allowed.
3. Static BIB entry upload is now allowed (but only on instance creation).
4. The following:

Jool 3's atomic configuration used to try to retain old values when instances were being updated. For example, if an existing instance's `logging-bib` option was set to the non-default `true`, then a `file update` using a JSON file that lacked the `logging-bib` tag would result in `logging-bib` remaining `true` rather than resetting.

Despite the good intentions, this turned to be inconsistent, and therefore hard to explain and error-prone. This is because of the databases.

If the blacklist database has prefixes `192.0.2/24`, `198.51.100/24`, `203.0.113/24`, then what should happen if the user runs atomic configuration with blacklist prefix `192.0.2.128/23`? Should Jool reject it because of collision? Did they meant to replace the first prefix? And if Jool treated it that way, then what would the user have to do to delete the other prefixes? Obviously, that was a dead end, so databases were always completely replaced as long as the base tag (`blacklist4` in this case) existed.

So individual `global` values survived reconfigurations, but database entries did not.

Starting from Jool 4, all tags work the same, which is to say, the JSON file is a snapshot of the ENTIRE configuration at a given time. Anything that's absent from the file will be mercilessly defaulted during updates.

This also leads to simpler code.
