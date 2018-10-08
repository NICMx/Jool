---
language: en
layout: default
category: Documentation
title: --instance
---

[Documentation](documentation.html) > [Userspace Application Arguments](documentation.html#userspace-application-arguments) > \--instance

# \--instance

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Arguments](#arguments)
   1. [Operations](#operations)
   2. [Options](#options)
4. [Examples](#examples)
   1. [General Examples](#general-examples)
   1. [Netfilter Examples](#netfilter-examples)
   2. [iptables Examples](#iptables-examples)

## Description

The following command actually does two things:

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">SIIT</span>
	<span class="distro-selector" onclick="showDistro(this);">NAT64</span>
</div>

<!-- SIIT -->
{% highlight bash %}
# modprobe jool_siit
{% endhighlight %}

<!-- NAT64 -->
{% highlight bash %}
# modprobe jool
{% endhighlight %}

1. Attach the kernel module to the kernel.  
   (In other words, it teaches the kernel about SIIT or NAT64.)
2. Adds a **Netfilter** translator instance to the network namespace the command is executed in.  
   (In other words, it actually hooks a translator to the current network stack.)

Incidentally, you can skip the second step by running the following version of the command:

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">SIIT</span>
	<span class="distro-selector" onclick="showDistro(this);">NAT64</span>
</div>

<!-- SIIT -->
{% highlight bash %}
# modprobe jool_siit no_instance
{% endhighlight %}

<!-- NAT64 -->
{% highlight bash %}
# modprobe jool no_instance
{% endhighlight %}

(See [`no_instance`](modprobe-siit.html#noinstance).)

Only one `jool` module, and also one `jool_siit` module, can be modprobed per kernel. Any modprobes after the first do nothing:

	# ip netns exec red   modprobe jool_siit   # success
	# ip netns exec red   modprobe jool        # success
	# ip netns exec green modprobe jool_siit   # no effect
	# ip netns exec green modprobe jool        # no effect
	# ip netns exec blue  modprobe jool_siit   # no effect
	# ip netns exec blue  modprobe jool        # no effect

So, if you want more Netfilter translators, you can use `--instance` to hook and unhook translators anywhere after a modprobe. (Regardless of `no_instance`.)

	# modprobe jool_siit no_instance                   # success
	# modprobe jool      no_instance                   # success
	# ip netns exec red   jool_siit --instance --add   # success
	# ip netns exec red   jool      --instance --add   # success
	# ip netns exec green jool_siit --instance --add   # success
	# ip netns exec green jool      --instance --add   # success
	# ip netns exec blue  jool_siit --instance --add   # success
	# ip netns exec blue  jool      --instance --add   # success

## Syntax

	(jool_siit | jool) --instance (
		[--display]
		| --add [--instance-name <name>] [--netfilter|--iptables]
		| --remove [--instance-name <name>]
		| --flush
	)

## Arguments

### Operations

* `--display`: Print a table listing all the instances known by Jool. (From all network namespaces.)
* `--add`: Creates and hooks an instance to the current network namespace.
* `--remove`: Unhooks and deletes the instance of the current network namespace.
* `--flush`: Unhooks and deletes all the instances in the current namespace.

### Options

| Flag              | Default   | Description                                                                        |
|-------------------|-----------|------------------------------------------------------------------------------------|
| `--instance-name` | "default" | Name of the instance to add or remove. Can be up to 15 printable ASCII characters. |
| `--netfilter`     | enabled   | Sit the instance on top of the Netfilter framework.                                |
| `--iptables`      | disabled  | Sit the instance on top of the iptables framework.                                 |

## Examples

### General Examples

	# jool --instance --add
	# jool --instance --add --instance-name alpha --netfilter
	# jool --instance --add --instance-name beta  --iptables
	#
	# ip netns add blue
	# ip netns exec blue jool --instance --add --instance-name alpha --netfilter
	#
	# jool --instance --display
	TODO

Notice that the namespace identifier is fairly nonsensical garbage. This is expected behavior for now, because namespace names do not exist in the kernel (in fact, some of them have no name), and so Jool has no concept of them.

	# jool --instance --remove --instance-name alpha
	# jool --instance --display
	TODO
	# jool --instance --flush
	# jool --instance --display
	TODO
	# ip netns exec blue jool --instance --flush
	# jool --instance --display
	TODO

### Netfilter Examples

Insert the module but do not attach an instance to the default namespace:

	# modprobe jool no_instance

Create two namespaces with two _local_ networks each:

<!-- TODO Add a diagram here, but I don't think it's that useful. -->

	# # First!
	# ip netns add blue
	# ip link add name to_blue type veth peer name to_world1
	# ip link set dev to_world1 netns blue
	#
	# ip link set to_blue up
	# ip addr add 2001:db8:1::8/96 dev to_blue
	# ip addr add 192.0.2.8/24 dev to_blue
	#
	# ip netns exec blue bash
	# ip link set to_world1 up
	# ip addr add 2001:db8:1::1/96 dev to_world1
	# ip addr add 192.0.2.1/24 dev to_world1
	# exit
	#
	# # Second!
	# ip netns add red
	# ip link add name to_red type veth peer name to_world2
	# ip link set dev to_world2 netns red
	#
	# ip link set to_blue up
	# ip addr add 2001:db8:2::8/96 dev to_red
	# ip addr add 203.0.113.8/24 dev to_red
	#
	# ip netns exec red bash
	# ip link set to_world2 up
	# ip addr add 2001:db8:2::1/96 dev to_world2
	# ip addr add 203.0.113.1/24 dev to_world2
	# exit

Add a NAT64 to each namespace:
	
	# ip netns exec blue bash
	# jool --instance --add
	# jool --pool6 --add 2001:db8:64::/96
	# exit
	#
	# ip netns exec red bash
	# jool --instance --add
	# jool --pool6 --add 2001:db8:46::/96
	# exit
	#
	# ip route add 2001:db8:64::/96 via 2001:db8:1::1
	# ip route add 2001:db8:46::/96 via 2001:db8:2::1

(I'm skipping the `sysctl` and `ethtool` commands to reduce clutter. Please add them in any serviceable environments.)

Ensure the NAT64s are different:

	# ip netns exec blue jool --pool6
	2001:db8:64::/96
	  (Fetched 1 entries.)
	# ip netns exec red jool --pool6
	2001:db8:46::/96
	  (Fetched 1 entries.)

Ping yourself through each NAT64:

	$ ping6 2001:db8:64::192.0.2.8 -c 4
	PING 2001:db8:64::192.0.2.8(2001:db8:64::c000:208) 56 data bytes
	64 bytes from 2001:db8:64::c000:208: icmp_seq=1 ttl=63 time=0.525 ms
	64 bytes from 2001:db8:64::c000:208: icmp_seq=2 ttl=63 time=0.263 ms
	64 bytes from 2001:db8:64::c000:208: icmp_seq=3 ttl=63 time=0.625 ms
	64 bytes from 2001:db8:64::c000:208: icmp_seq=4 ttl=63 time=0.298 ms

	--- 2001:db8:64::192.0.2.8 ping statistics ---
	4 packets transmitted, 4 received, 0% packet loss, time 3001ms
	rtt min/avg/max/mdev = 0.263/0.427/0.625/0.154 ms
	$ ping6 2001:db8:46::203.0.113.8 -c 4
	PING 2001:db8:46::203.0.113.8(2001:db8:46::cb00:7108) 56 data bytes
	64 bytes from 2001:db8:46::cb00:7108: icmp_seq=1 ttl=63 time=0.236 ms
	64 bytes from 2001:db8:46::cb00:7108: icmp_seq=2 ttl=63 time=0.422 ms
	64 bytes from 2001:db8:46::cb00:7108: icmp_seq=3 ttl=63 time=0.480 ms
	64 bytes from 2001:db8:46::cb00:7108: icmp_seq=4 ttl=63 time=0.154 ms

	--- 2001:db8:46::203.0.113.8 ping statistics ---
	4 packets transmitted, 4 received, 0% packet loss, time 3002ms
	rtt min/avg/max/mdev = 0.154/0.323/0.480/0.132 ms

Check out each NAT64's [state](usr-flags-session.html):

	# ip netns exec blue jool --session --icmp --numeric
	ICMP:
	---------------------------------
	Expires in 42 seconds
	Remote: 192.0.2.8#62253	2001:db8:1::8#3206
	Local: 192.0.2.1#62253	2001:db8:64::c000:208#3206
	---------------------------------
	  (Fetched 1 entries.)
	# ip netns exec red jool --session --icmp --numeric
	ICMP:
	---------------------------------
	Expires in 48 seconds
	Remote: 203.0.113.8#62941	2001:db8:2::8#3207
	Local: 203.0.113.1#62941	2001:db8:46::cb00:7108#3207
	---------------------------------
	  (Fetched 1 entries.)

<!-- TODO add a tcpdump... dump? -->

### iptables Examples

It's important to note that the rule and the instance need separate configurations because they are independent components. First, let's create and configure the instance:

	# modprobe jool no_instance
	# jool --instance --add --instance-name alpha --iptables
	# jool --instance-name alpha --pool6 --add 64:ff9b::/96
	# jool --instance-name alpha --pool4 --add 192.0.2.1

It's also important to note that you need at least two rules per instance. This is because they are the entry point for packets that will reach the instance, and so you need one for each of the IP protocols:

	# ip6tables -t mangle -A PREROUTING --destination 64:ff9b::/96 -j JOOL --instance-name alpha
	# iptables  -t mangle -A PREROUTING --destination 192.0.2.1    -j JOOL --instance-name alpha

Convince yourself that this is fairly standard iptables fare:

	# ip6tables -t mangle -L
	TODO output
	# iptables  -t mangle -L
	TODO output

And try performing some translation (in this case, from some other IPv6 node):

	$ ping6 64:ff9b::8.8.8.8
	TODO output
