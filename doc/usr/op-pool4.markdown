---
layout: documentation
title: Documentation - Tutorial 3
---

# [Doc](doc-index.html) > [Operation](doc-index.html#further-operation) > The IPv4 Pool

![Fig.1 - Network from Scenario 3](images/tut2.3-network.svg)

Here's a theoretical packet that might travel from C to E:

	Source: Address 2001:db8:2::10, port 1234 (random)
	Destination: Address 64::192.0.2.10, port 80 (i.e. trying to reach a website)

Regarding the source port field: It is well known that a port is a two-byte value, which means that you can run out of them. This is normally not an issue, since 65536 per node is at least a fairly reasonable amount.

The above packet might be translated by J into something like this:

	Source: 192.0.2.2#1234
	Destination: 192.0.2.10#80

And Jool will memorize that 2001:db8:2::10#1234 is related to 192.0.2.2#1234. E will answer

	Source: 192.0.2.10#80
	Destination: 192.0.2.2#1234

And by virtue of its memory, Jool will know it has to translate that into

	Source: 64::192.0.2.10#80
	Destination: 2001:db8:2::10#1234

But what if D generates the following packet?

	Source: 2001:db8:2::11#1234
	Destination: 64::192.0.2.10#80

Jool cannot translate it into

	Source: 192.0.2.2#1234
	Destination: 192.0.2.10#80

Because it will then have two contradictory mappings. Which one will it use when E's answer shows its face?

1. 2001:db8:2::10#1234 <-> **192.0.2.2#1234**
2. 2001:db8:2::11#1234 <-> **192.0.2.2#1234**

The solution is to mask not only addresses, but ports as well. Instead of generating the aforementioned packet, Jool will generate this:

	Source: 192.0.2.2#6326
	Destination: 192.0.2.10#80

And the [BIB](misc-bib.html) will look like this:

1. 2001:db8:2::10#1234 <-> 192.0.2.2#1234
2. 2001:db8:2::11#1234 <-> 192.0.2.2#6326

To what I'm getting is, all IPv6 nodes share the same IPv4 address (as opposed to stateless NAT64). This is good because you don't need one IPv4 address per IPv6 node, but at the same time you need to be aware that Jool might run out of ports.

C and D used one port each (and they even happened to be the same one), but Jool still had to use two. Each IPv6 node has 65536 ports to work with, but because they all share the same IPv4 address, as a group, they can use up to 65536 ports via the translator. The more IPv6 nodes you have, the faster J will run out of ports.

How do you make up for this? You can give Jool more addresses. You will get 64k fresh ports for each IPv4 address you throw in. If the IPv4 side is indeed an ISP, do remember that it will be the one who'll provide the addresses.

You can specify up to 5 addresses during module insertion:

{% highlight bash %}
user@J:~# /sbin/modprobe jool pool4="192.0.2.2, 192.0.2.3, 192.0.2.4, 192.0.2.5, 192.0.2.6"
{% endhighlight %}

If you need more, you can add them using the [userspace application](usr-flags-pool4.html):

{% highlight bash %}
user@J:~# jool --pool4 --add --address 192.0.2.7
user@J:~# jool --pool4 --add --address 192.0.2.8
user@J:~# # etc.
{% endhighlight %}

And remember that Linux might have to answer ARP requests for them:

{% highlight bash %}
user@J:~# /sbin/ip address add 192.0.2.2/24 dev eth1
user@J:~# /sbin/ip address add 192.0.2.3/24 dev eth1
user@J:~# /sbin/ip address add 192.0.2.4/24 dev eth1
user@J:~# /sbin/ip address add 192.0.2.5/24 dev eth1
user@J:~# # etc.
{% endhighlight %}

