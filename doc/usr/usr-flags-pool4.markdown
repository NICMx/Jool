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

Though the userspace application's interface is very similar, the pool behaves differently depending on Jool's "stateness".

On Stateless Jool, the IPv4 pool is a whitelist that dictates whether an address should be translatable using the NAT64 prefix or not.

On Stateful Jool, the IPv4 pool is the subset of the node's address which should be used for translation. _This might change in future versions_.

Also, because the [implementation in Stateful Jool leaves a lot to be desired](https://github.com/NICMx/NAT64/issues/117#issuecomment-66942415), editing the pool is very slow and memory-demanding. You want to avoid managing prefix lenghts of /24 and below in this case.

## Syntax

(`$(jool)` can be either `jool_stateless` or `jool_stateful`.)

	$(jool) --pool4 [--display]
	$(jool) --pool4 --count
	$(jool) --pool4 --add <IPv4 prefix>
	$(jool) --pool4 --remove <IPv4 prefix> [--quick]
	$(jool) --pool4 --flush [--quick]

## Options

### Operations

* `--display`: The pool's addresses are printed in standard output. This is the default operation.
* `--count`: The number of _addresses_ (not prefixes) in the pool is printed in standard output.  
For example, if all you have is a /30 prefix, expect "4" as output.
* `--add`: Uploads `<IPv4 address>` to the pool.
* `--remove`: Deletes from the tables the address `<IPv4 address>`.
* `--flush`: Removes all addresses from the pool.

### \--quick

See [`--quick`](usr-flags-quick.html). Only available on Stateful Jool.

## Examples

Display the current addresses:

{% highlight bash %}
$ jool_stateless --pool4 --display
192.0.2.0/28
198.51.100.0/30
203.0.113.8/32
  (Fetched 3 prefixes.)
{% endhighlight %}

Display only the address count:

{% highlight bash %}
$ jool_stateless --pool4 --count
21
{% endhighlight %}

(That's /28 + /30 + /32 = 16 + 4 + 1)

Remove a couple of entries:

{% highlight bash %}
# jool_stateless --pool4 --remove 192.0.2.0/28
# jool_stateless --pool4 --remove 198.51.100.0/30
{% endhighlight %}

Return one entry:

{% highlight bash %}
# jool_stateless --pool4 --add 192.0.2.0/28
{% endhighlight %}

