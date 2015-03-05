---
layout: documentation
title: Documentation - Flags > IPv6 Pool
---

[Documentation](doc-index.html) > [Userspace Application](doc-index.html#userspace-application) > [Flags](usr-flags.html) > \--pool6

# \--pool6

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Options](#options)
   1. [Operations](#operations)
   2. [`--quick`](#quick)
4. [Examples](#examples)

## Description

Interacts with Jool's IPv6 pool. The pool dictates which packets coming from the IPv6 side are processed; if an incoming packet's destination address has one of the IPv6 prefixes, the packet is translated. Otherwise it is handed to the kernel to either be forwarded in some other way or handed to the upper layers.

## Syntax

(`$(jool)` can be either `jool_siit` or `jool`.)

	$(jool) --pool6 [--display]
	$(jool) --pool6 --count
	$(jool) --pool6 --add <IPv6 prefix>
	$(jool) --pool6 --remove <IPv6 prefix> [--quick]
	$(jool) --pool6 --flush [--quick]

## Options

### Operations

* `--display`: The pool's prefixes are printed in standard output. This is the default operation.
* `--count`: The number of prefixes in the pool is printed in standard output.
* `--add`: Uploads `<prefix>` to the pool.
* `--remove`: Deletes from the tables the prefix `<prefix>`.
* `--flush`: Removes all prefixes from the pool.

### `--quick`

See [`--quick`](usr-flags-quick.html). Only available on Stateful Jool.

## Examples

Display the current prefixes:

{% highlight bash %}
$ jool --pool6 --display
64:ff9b::/96
  (Fetched 1 prefixes.)
{% endhighlight %}

Display only the prefix count:

{% highlight bash %}
$ jool --pool6 --count
1
{% endhighlight %}

Remove the default prefix:

{% highlight bash %}
$ jool --pool6 --remove 64:ff9b::/96
{% endhighlight %}

Add a sample prefix:

{% highlight bash %}
$ jool --pool6 --add 2001:db8::/64
{% endhighlight %}

Destroy all prefixes. Do not bother cleaning up the garbage:

{% highlight bash %}
$ jool --pool6 --flush --quick
{% endhighlight %}

