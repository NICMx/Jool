---
language: en
layout: default
category: Documentation
title: IPv4 Transport Address Pool
---

[Documentation](documentation.html) > [Runs](documentation.html#runs) > [Stateful NAT64](mod-run-stateful.html) > IPv4 Pool

# IPv4 Transport Address Pool

If you're familiar with iptables and masquerade, all you probably need to know is that the following:

	jool --pool4 --add --tcp 192.0.2.1 5000-6000

is spiritually equivalent to

	ip addr add 192.0.2.1 dev (...)
	iptables -t nat -A POSTROUTING -p TCP -j MASQUERADE --to-ports 5000-6000

-----------------------------

Just like a NAT, a Stateful NAT64 allows an indeterminate amount of clients to share a few IPv4 addresses by strategically distributing their traffic accross its own transport address domain.

We call this "transport address domain" the "IPv4 pool". ("pool4" for short.)

To illustrate:

![Fig. 1 - n6's request](../images/flow/pool4-simple1-en.svg "Fig. 1 - n6's request")

In Jool, we write transport addresses in the form `<IP address>#<port>` (as opposed to `<IP address>:<port>`). The packet above has source IP address `2001:db8::8`, source port (TCP or UDP) 5123, destination address `64:ff9b::192.0.2.24`, and destination port 80.

Assuming pool4 holds transport addresses 203.0.113.1#5000 through 203.0.113.1#6000, one possible translation of the packet is this:

![Fig. 2 - T's translation - version 1](../images/flow/pool4-simple2-en.svg "Fig. 2 - T's translation - version 1")

Another one, equally valid, is this:

![Fig. 3 - T's translation - version 2](../images/flow/pool4-simple3-en.svg "Fig. 3 - T's translation - version 2")

NAT64s are not overly concerned with retaining source ports. In fact, for security reasons, [recommendations exist to drive NAT64s as unpredictable as possible]({{ site.draft-nat64-port-allocation }}).

When defining the addresses and ports that will belong to your pool4, you need to be aware that they must not collide with other services or clients within the same machine. If _T_ tries to open a connection from transport address `192.0.2.1#5000` and at the same time a translation yields source transport address `192.0.2.1#5000`, Jool will end up combining the the information transmitted in both connections.

Linux's ephemeral port range defaults to 32768-61000. Therefore, Jool's port range for any given address defaults to 61001-65535. [You can change the former by tweaking sysctl `sys.net.ipv4.ip_local_port_range`, and the latter by means of `--pool4 --add` userspace application commands](usr-flags-pool4.html#notes).

