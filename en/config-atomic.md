---
language: en
layout: default
category: Documentation
title: Session synchronization
---

[Documentation](documentation.html) > [Other Configuration](documentation.html#other-configuration) > Atomic Configuration

# Atomic Configuration

## Index

1. [Introduction](#introduction)
2. [SIIT](#siit)
3. [NAT64](#nat64)

## Introduction

"Atomic Configuration" is a means to set up more than one of Jool's parameters in a single `jool`/`jool_siit` command. The idea is that either all the configuration is applied at once (on success) or none of it (on any failures). This frees you from having to handle mid-configuration exceptions and have to roll back half commits.

You can also think of it as "file" configuration mode, since that's the means by which Atomic Configuration is handled. You still need the userspace applications though.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">SIIT</span>
	<span class="distro-selector" onclick="showDistro(this);">NAT64</span>
</div>

<!-- SIIT -->
{% highlight bash %}
# jool_siit --file /path/to/config
{% endhighlight %}

<!-- NAT64 -->
{% highlight bash %}
# jool --file /path/to/config
{% endhighlight %}

The configuration is read from a Json file. Since the options are the same as their userspace application counterparts, I will simply showcase a couple of full Json examples and link to the app documentation.

Every tag is optional. Section tags (such as `global`, `pool6` and `eamt`) and global parameters (eg. `manually-enabled`, `tos` and `f-args`) that you skip will be left intact as they used to be. For example, if your RFC6791 pool contains address `192.0.2.32` and you omit the `pool6791` tag in the file, `192.0.2.32` will remain in pool6791 after the new configuration is applied. If, on the other hand, you intend to clear pool6791, you need to explicitly write an empty `pool6791` tag.

Without further ado:

## SIIT

<pre><code>{
	"global": {
		"<a href="usr-flags-global.html#enable---disable">manually-enabled</a>": false,
		"<a href="usr-flags-global.html#zeroize-traffic-class">zeroize-traffic-class</a>": true,
		"<a href="usr-flags-global.html#override-tos">override-tos</a>": false,
		"<a href="usr-flags-global.html#tos">tos</a>": 254,
		"<a href="usr-flags-global.html#mtu-plateaus">mtu-plateaus</a>": [1, 2, 3, 4, 5, 6],
		"<a href="usr-flags-global.html#amend-udp-checksum-zero">amend-udp-checksum-zero</a>": true,
		"<a href="usr-flags-global.html#eam-hairpin-mode">eam-hairpin-mode</a>": 1,
		"<a href="usr-flags-global.html#randomize-rfc6791-addresses">randomize-rfc6791-addresses</a>": false,
		"<a href="usr-flags-global.html#rfc6791v6-prefix">rfc6791v6-prefix</a>": null
	},

	"<a href="usr-flags-pool6.html">pool6</a>": "64:ff9b::/96",

	"<a href="usr-flags-eamt.html">eamt</a>": [
		{
			"ipv6 prefix": "2001:db8:1::/128",
			"ipv4 prefix": "192.0.2.0"
		},
		{
			"ipv6 prefix": "2001:db8:2::",
			"ipv4 prefix": "192.0.2.1/32"
		},
		{
			"ipv6 prefix": "2001:db8:3::/124",
			"ipv4 prefix": "192.0.2.16/28"
		}
	],

	"<a href="usr-flags-blacklist.html">blacklist</a>": [
		"198.51.100.0",
		"198.51.100.2/32",
		"198.51.100.32/27"
	],

	"<a href="usr-flags-pool6791.html">pool6791</a>": [
		"203.0.113.0",
		"203.0.113.1/32",
		"203.0.113.64/26"
	]
}</code></pre>

## NAT64

There is one major caveat here: atomic modification of static BIB entries is [not supported](https://github.com/NICMx/Jool/blob/eef858e5a3998b6739e13201dbd4b36f014e30d3/usr/common/target/json.c#L635). This is because the current implementation of BIB/session is not suitable to guarantee the atomicity of multiple modifications.

Sorry. This does not necessarily mean it will never be implemented, but there are no plans for now.

<pre><code>{
	"global": {
		"<a href="usr-flags-global.html#enable---disable">manually-enabled</a>": false,

		"<a href="usr-flags-global.html#zeroize-traffic-class">zeroize-traffic-class</a>": true,
		"<a href="usr-flags-global.html#override-tos">override-tos</a>": false,
		"<a href="usr-flags-global.html#tos">tos</a>": 254,
		"<a href="usr-flags-global.html#mtu-plateaus">mtu-plateaus</a>": [1, 2, 3, 4, 5, 6],
		"<a href="usr-flags-global.html#maximum-simultaneous-opens">maximum-simultaneous-opens</a>": 16,
		"<a href="usr-flags-global.html#source-icmpv6-errors-better">source-icmpv6-errors-better</a>": true,
		"<a href="usr-flags-global.html#f-args">f-args</a>": 10,
		
		"<a href="usr-flags-global.html#logging-bib">logging-bib</a>": true,
		"<a href="usr-flags-global.html#logging-session">logging-session</a>": true,

		"<a href="usr-flags-global.html#address-dependent-filtering">address-dependent-filtering</a>": true,
		"<a href="usr-flags-global.html#drop-icmpv6-info">drop-icmpv6-info</a>": true,
		"<a href="usr-flags-global.html#drop-externally-initiated-tcp">drop-externally-initiated-tcp</a>": true,

		"<a href="usr-flags-global.html#udp-timeout">udp-timeout</a>": 213897,
		"<a href="usr-flags-global.html#tcp-est-timeout">tcp-est-timeout</a>": 218937891,
		"<a href="usr-flags-global.html#tcp-trans-timeout">tcp-trans-timeout</a>": 289013021,
		"<a href="usr-flags-global.html#icmp-timeout">icmp-timeout</a>": 129038,
		"<a href="usr-flags-global.html#fragment-arrival-timeout">fragment-arrival-timeout</a>": 190238,

		"<a href="usr-flags-global.html#ss-enabled">ss-enabled</a>": true,
		"<a href="usr-flags-global.html#ss-flush-asap">ss-flush-asap</a>": false,
		"<a href="usr-flags-global.html#ss-flush-deadline">ss-flush-deadline</a>": 1000,
		"<a href="usr-flags-global.html#ss-capacity">ss-capacity</a>": 256,
		"<a href="usr-flags-global.html#ss-max-payload">ss-max-payload</a>": 600
	},

	"<a href="usr-flags-pool6.html">pool6</a>": "64:ff9b::/96",

	"<a href="usr-flags-pool4.html">pool4</a>": [
		{
			"mark": 1,
			"protocol": "UDP",
			"prefix": "192.0.2.1",
			"port range": "61001-62000"
		},
		{
			"mark": 1,
			"protocol": "ICMP",
			"prefix": "192.0.2.1/32",
			"port range": "1000-2000"
		},
		{
			"protocol": "TCP",
			"prefix": "192.0.2.1/31"
		}
	]
}</code></pre>
