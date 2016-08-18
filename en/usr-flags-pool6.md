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
3. [Arguments](#arguments)
   1. [Operations](#operations)
   2. [Options](#options)
4. [Examples](#examples)

## Description

Interacts with Jool's IPv6 pool. This "pool" contains the [RFC 6052](https://tools.ietf.org/html/rfc6052) prefix, which is the basic translation prefix to be added or removed from IPv4 addresses in [vanilla SIIT](intro-xlat.html#siit-traditional) and [Stateful NAT64](intro-xlat.html#stateful-nat64).

Even though we (and the RFC) call it a "pool", it doesn't really make sense for it to contain more than one prefix because there's currently no way to map them to interfaces or [pool4](pool4.html) entries. This might change in the future. NAT64 Jool allows you to inject more than one prefix to the pool, but only for backwards compatibility reasons. (The translating code always uses the first prefix only.) SIIT Jool does not allow you to input more than one prefix.

If the pool is empty, Jool will be unable to address-translate via RFC 6052 (but SIIT Jool can still do so via the [EAMT](eamt.html)).

## Syntax

	(jool_siit | jool) --pool6 (
		[--display] [--csv]
		| --count
		| --add <IPv6-prefix> [--force]
		| --remove <IPv6-prefix>
		| --flush
	)

## Arguments

### Operations

* `--display`: The pool's prefixes are printed in standard output. This is the default operation.
* `--count`: The number of prefixes in the pool is printed in standard output.
* `--add`: Uploads `<IPv6-prefix>` to the pool.  
  As per RFC 6052, the prefix length must be 32, 40, 48, 56, 64 or 96.  
  In addition, u-bit (the ninth byte of the prefix) must be zero. This constraint [isn't very useful]({{ site.repository-url }}/issues/174), so you can overcome it using `--force`.
* `--remove`: Deletes the prefix `<IPv6-prefix>` from the pool.
* `--flush`: Removes all prefixes from the pool.

### Options

| **Flag** | **Description** |
| `--csv` | Print the table in [_Comma/Character-Separated Values_ format](http://en.wikipedia.org/wiki/Comma-separated_values). This is intended to be redirected into a .csv file. |
| `--force` | Upload the prefix even if u-bit is nonzero. See the [relevant issue]({{ site.repository-url }}/issues/174). |

> ![Note!](../images/warning.svg) The `--quick` option is no longer available in `--pool6` mode since Jool 3.5!
> 
> This is because consistency between pool6 and the session tables became a key prerequisite for significant optimizations to BIB/session.

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

Remove the [Well-Known Prefix](https://tools.ietf.org/html/rfc6052#section-2.1):

{% highlight bash %}
$ jool --pool6 --remove 64:ff9b::/96
{% endhighlight %}

Add a sample prefix:

{% highlight bash %}
$ jool --pool6 --add 2001:db8::/64
{% endhighlight %}

