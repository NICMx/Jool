---
language: en
layout: default
category: Documentation
title: --pool6
---

[Documentation](documentation.html) > [Userspace Application Arguments](documentation.html#userspace-application-arguments) > \--pool6

# \--pool6

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Options](#options)
   1. [Operations](#operations)
   2. [`--quick`](#quick)
4. [Examples](#examples)

## Description

Interacts with Jool's IPv6 pool. This "pool" contains the [RFC 6052](https://tools.ietf.org/html/rfc6052) prefix, which is the basic translation prefix to be added or removed from IPv4 addresses in [vanilla SIIT](intro-nat64.html#siit-traditional) and [Stateful NAT64](intro-nat64.html#stateful-nat64).

Even though we (and the RFC) call it a "pool", it doesn't really make sense for it to contain more than one prefix because there's currently no way to map them to interfaces or [pool4](pool4.html) entries. This might change in the future. NAT64 Jool allows you to inject more than one prefix to the pool, but only for backwards compatibility reasons (the translating code always uses the first prefix only). SIIT Jool does not allow you to input more than one prefix.

If the pool is empty, Jool will be unable to address-translate via RFC 6052 (but can still do so via the [EAMT](eamt.html)).

## Syntax

(`$(jool)` can be either `jool_siit` or `jool`.)

	$(jool) --pool6 [--display]
	$(jool) --pool6 --count
	$(jool) --pool6 --add <IPv6 prefix> [--force]
	$(jool) --pool6 --remove <IPv6 prefix> [--quick]
	$(jool) --pool6 --flush [--quick]

## Options

### Operations

* `--display`: The pool's prefixes are printed in standard output. This is the default operation.
* `--count`: The number of prefixes in the pool is printed in standard output.
* `--add`: Uploads `<prefix>` to the pool.  
  As per RFC 6052, the prefix length must be 32, 40, 48, 56, 64 or 96.  
  In addition, u-bit (the ninth byte of the prefix) must be zero. This constraint [isn't too useful](https://github.com/NICMx/NAT64/issues/174), so you can overcome it by using `--force`.
* `--remove`: Deletes the prefix `<prefix>` from the pool.
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

