---
layout: documentation
title: Documentation - Userspace Application
---

# [Doc](doc-index.html) > [Userspace App](doc-index.html#userspace-application) > [Flags](usr-flags.html) > \--pool4

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Options](#options)
   1. [Operations](#operations)
   2. [\--quick](#quick)
4. [Examples](#examples)

## Description

Interacts with Jool's IPv4 pool. The pool dictates which packets coming from the IPv4 side are processed; if an incoming packet's destination address is listed in the pool, the packet is translated. Otherwise it is handed to the kernel to either be forwarded in some other way or handed to the upper layers.

## Syntax

	jool --pool4 [--display]
	jool --pool4 --count
	jool --pool4 --add --address <IPv4 address>
	jool --pool4 --remove --address <IPv4 address> [--quick]
	jool --pool4 --flush [--quick]

## Options

### Operations

* `--display`: The pool's addresses are printed in standard output. This is the default operation.
* `--count`: The number of addresses in the pool is printed in standard output.
* `--add`: Uploads `<IPv4 address>` to the pool.
* `--remove`: Deletes from the tables the address `<IPv4 address>`.
* `--flush`: Removes all addresses from the pool.

### \--quick

See [`--quick`](usr-flags-quick.html).

## Examples

{% highlight bash %}
$ # Display the current addresses.
$ jool --pool4
192.168.2.1
192.168.2.2
192.168.2.3
192.168.2.4
  (Fetched 4 addresses.)
$ # Display only the address count.
$ jool --pool4 --count
4
$ # Remove a couple of default addresses.
$ jool --pool4 --remove --address 192.168.2.2
$ jool --pool4 --remove --address 192.168.2.3 --quick
$ # Return one address.
$ jool --pool4 --add --address 192.168.2.2
{% endhighlight %}

