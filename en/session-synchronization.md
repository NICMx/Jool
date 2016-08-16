---
language: en
layout: default
category: Documentation
title: Session synchronization
---

[Documentation](documentation.html) > [Other Sample Runs](documentation.html#other-sample-runs) > Session Synchronization

# Session Synchronization

## Index

1. [Introduction](#introduction)
2. [Sample Network](#sample-network)
3. [Traffic Flow Explanation](#traffic-flow-explanation)
	1. [Session Synchronization Disabled](#session-synchronization-disabled)
	2. [Session Synchronization Enabled](#session-synchronization-enabled)
4. [Architecture](#architecture)
5. [Basic Tutorial](#basic-tutorial)
	1. [Daemon](#daemon)
	2. [Load Balancer](#load-balancer)
	3. [Kernel Module](#kernel-module)
6. [Configuration](#configuration)
	1. [`jool`](#jool)
	2. [`netsocket.json`](#netsocketjson)
		1. [`multicast-address`](#multicast-address)
		2. [`multicast-port`](#multicast-port)
		3. [`in interface`](#in-interface)
		4. [`out interface`](#out-interface)
		5. [`reuseaddr`](#reuseaddr)
		6. [`ttl`](#ttl)
7. [Persistent Daemon](#persistent-daemon)

## Introduction

The fact that stock NAT64 is stateful makes redundancy difficult. You can't simply configure two independent NAT64s and expect that one will serve as a backup for the other should the latter fall.

> Well, you can in reality, but users will notice that they need to re-establish all their lasting connections during a failure since the new NAT64 needs to recreate all the [dynamic mappings](bib.html) (and their sessions) that the old NAT64 lost.

Since version 3.5, Jool ships with a daemon that allows constant synchronization of sessions across Jool instances so you can work around this limitation. The purpose of this document is to explain and exemplify its usage.

Session Synchronization (hereby abbreviated as "SS") applies to NAT64 Jool only. SIIT stores no state, and therefore it has no difficulties regarding failover clustering.

## Sample Network

![Figure 1 - Sample Network](../images/network/ss.svg)

Nodes `J`, `K` and `L` will be Stateful NAT64s. Their configuration will be only slightly different, and any number of extra backup NAT64s can be appended by replicating similar configuration through additional nodes. You intend to have at least two of these.

Network `10.0.0.0/24` is a private network where the sessions will be advertised as the NAT64s serve traffic through their other interfaces. You want this network to be dedicated because sessions are confidential information to some extent, and as a result you don't want this information to leak elsewhere.

## Traffic Flow Explanation

First, let's analyze what happens when you create multiple Jool instances but do not enable SS:

### Session Synchronization Disabled

IPv6 node `n6` will interact with IPv6 node `n4` via `J`. As is natural of NAT64, `J` will store a mapping (and a session) to service this connection:

![Figure - joold](../images/flow/ss-basic.svg)

During `n4` and `n6`'s conversation, `J` dies. This is what happens when `n4` follows with a packet:

FigFigFig

And `n6` doen't fare much better either:

FigFigFigFig

The problem lies in the NAT64s not sharing their databases. Let's fix that:

### Session Synchronization Enabled

When either `n6` or `n4` first opens the connection, `J` generates two packets: One is the translated message and the other is a multicast through the private network, informing everyone interested of the new connection:

FigFigFigFigFig

So when `J` dies, `K` has everything it needs to impersonate `J` and continue the conversation as uninterrupted as possible:

FigFigFigFigFigFig

In reality, _every_ translated packet will fork an SS packet, because ongoing traffic tends to update sessions, and the other NAT64 instances need to also be aware of these changes.

## Architecture

Each machine hosting a NAT64 will also hold a daemon that will bridge SS traffic between the private network and its Jool instance. This daemon is named `joold`. So the kernel modules will generate SS traffic and offset the delivery task to these daemons:

![Figure - joold](../images/network/joold.svg)

Why is the daemon necessary? because kernel modules cannot open IP sockets; at least not in a reliable and scalable manner.

Synchronizing sessions is _all_ the daemon does; the traffic redirection part is delegated to other protocols (TODO I don't think this redirection thing is explained too well above). [Keepalived](http://www.keepalived.org/) is the implementation that takes care of this in the sample configuration below, but any other load balancer should also get the job done.

In this proposed/inauguratory implementation, SS traffic is distributed through an IPv4 or IPv6 unencrypted TCP connection. You might want to cast votes on the issue tracker or propose code if you favor some other solution.

It is also important to note that SS is relatively resource-intensive; its traffic is not only _extra_ traffic, but it must also do two full U-turns to userspace before reaching its destination:

![Figure - joold U-turns](../images/network/joold-uturn.svg)

It is possible to configure SS in such a manner that sessions queue themselves as much as possible before being fetched, so they can be wrapped in as few packets as possible. Of course, the price is reliability: Queued sessions will be wasted if their NAT64 dies before sending them.

There are two operation modes in which SS can be used:

1. Active/Passive: One Jool instance serves traffic at any given time, the other ones serve as backup. The load balancer redirects traffic when the current active NAT64 dies.
2. Active/Active: All Jool instances serve traffic. The load balancer distributes traffic so no NAT64 is too heavily encumbered.

Active/Active is discouraged for two reasons:

First, the Jool instances cannot ensure their session databases will be synchronized at all times before any traffic is translated; this would be prohibitely expensive. If the v4/v6 traffic is faster than the private network traffic, a race can happen:

FigFigFigFigFigFigFigFig

The endnodes will have to retry the connection.

TODO get into TCP state machine details? "There is no recovery from this situation; `J`'s session will override `K`'s session and the knowledge that a SYN packet was issued by `n4` will be lost. This drops the reliability of the TCP state machine,"

The second problem is Simultaneous Open. TODO explain

Both problems can be mitigated if the load balancer can ensure that traffic belonging to a specific connection always traverses the same NAT64. (TODO can load balancers do that? It sounds far-fetched.)

## Basic Tutorial

This is a sample of the Active/Passive model.

### Network

First, configure the NAT64s:

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">J</span>
	<span class="distro-selector" onclick="showDistro(this);">K</span>
</div>

<!-- J -->
{% highlight bash %}
ip addr add 2001:db8::1/96 dev eth0
ip addr add 192.0.2.1/24 dev eth1
ip addr add 10.0.0.2/24 dev eth2

ethtool --offload eth0 gro off
ethtool --offload eth0 lro off
ethtool --offload eth1 gro off
ethtool --offload eth1 lro off
sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1
modprobe jool pool6=64:ff9b::/96
{% endhighlight %}

<!-- K -->
{% highlight bash %}
# X
# X
ip addr add 10.0.0.2/24 dev eth2

ethtool --offload eth0 gro off
ethtool --offload eth0 lro off
ethtool --offload eth1 gro off
ethtool --offload eth1 lro off
sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1
modprobe jool pool6=64:ff9b::/96
{% endhighlight %}

This is generally usual boilerplate Jool mumbo jumbo. All that's special is the lack of address configuration in `K`'s translating interfaces; the load balancer will take care of populating these if `J` dies.

### Kernel module

Because forking SS sessions on every translated packet is not free (performance-wise), the kernel module is not SS-enabled by default. The fact that the module and the daemon are separate binaries enhances the importance of this fact; starting the daemon is not, by itself, enough to get sessions synchronized.

	# jool --synch-enable

This asks the module to open a channel to userspace and start trading SS sessions.

### Daemon

`joold` reads the configuration of its network socket from a Json file whose name is `netsocket.json` by default.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">J</span>
	<span class="distro-selector" onclick="showDistro(this);">K</span>
</div>

{% highlight json %}
{
	"multicast-address": "226.4.6.4",
	"multicast-port": "6464",
	"in interface": "10.0.0.1",
	"out interface": "10.0.0.1",
	"reuseaddr": 1
}
{% endhighlight %}

{% highlight json %}
{
	"multicast-address": "226.4.6.4",
	"multicast-port": "6464",
	"in interface": "10.0.0.2",
	"out interface": "10.0.0.2",
	"reuseaddr": 1
}
{% endhighlight %}

A description of each field can be found [below](TODO). For now, suffice to say that the nodes will send and receive SS traffic through the multicast address `226.4.6.4` on port `6464`.

Start the "daemon" in the foreground so you can see error messages (if any) easily:

	$ joold /path/to/netsocket.json

(TODO don't forget the syslog stuff)

If everything looks tidy, send the process to the background (Ctrl+Z then run `bg`):

	^Z
	$ bg

Do this on both `J` and `K`.

As far as Jool is concerned, that would be all. If `J` is translating traffic, you should see its sessions being mirrored in `K`:

	user@K:~/# jool -sn

### Load Balancer

This is not a tutorial on Keepalived, but I'll try explaining the important stuff.

Download, compile and install Keepalived:

	$ # Find the latest at http://www.keepalived.org/download.html
	$ wget www.keepalived.org/software/keepalived-X.Y.Z.tar.gz
	$ tar -xzf keepalived*
	$ cd keepalived*
	$ ./configure
	$ make
	# make install

Create `/etc/keepalived/keepalived.conf` and paste something like the following. See `man 5 keepalived.conf` for more information.

	# Keepalived will monitor this action.
	# The userspace application `jool` fails when the kernel module is not
	# responding, so we will run it every two seconds to monitor its health.
	# In reality, you might want to test more than this (such as the state
	# of the interfaces and whatnot), but for the purposes of this tutorial
	# this should be enough.
	vrrp_script check_jool {
		script "jool"
		interval 2
	}

	vrrp_instance VI_1 {
		interface eth2
		state MASTER
		# J is our main NAT64, so grant it the most priority.
		priority 500

		# This is just a random 0-255 id that must be the same for all
		# the Keepalived instances.
		virtual_router_id 64
		# Force Keepalived to use the prvate interface.
		unicast_src_ip 10.0.0.1
		# Addresses of the other peers.
		# TODO do we really need this?
		unicast_peer {
			10.0.0.2
		}

		# Reference the monitor 
		track_script {
			check_jool
		}

		# Script to run when Keepalived enters the MASTER state.
		# (ie. when this Jool becomes the active one.)
		notify_master /etc/keepalived/master.sh

		# Script to run when Keepalived enters the BACKUP state.
		# (ie. when this Jool is no longer the active one, but it's
		# still alive)
		notify_backup /etc/keepalived/backup.sh

		# Script to run when Keepalived enters the FAULT state.
		# (ie. when this Jool is not responding.)
		notify_fault  /etc/keepalived/fault.sh
	}

These are the respective referenced scripts:

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">master.sh</span>
	<span class="distro-selector" onclick="showDistro(this);">backup.sh</span>
	<span class="distro-selector" onclick="showDistro(this);">fault.sh</span>
</div>

<!-- Master -->
{% highlight bash %}
ip addr add 2001:db8::1/96 dev eth0
ip addr add 192.0.2.1/24 dev eth1
{% endhighlight %}

<!-- Backup -->
{% highlight bash %}
# --joold --advertise forces this instance to yell its entire session database
# in the network.
# We want this because the new master was likely just modprobed and therefore
# its database is empty.
jool --joold --advertise

ip addr del 2001:db8::1/96 dev eth0
ip addr del 192.0.2.1/24 dev eth1
{% endhighlight %}

<!-- Fault -->
{% highlight bash %}
ip addr del 2001:db8::1/96 dev eth0
ip addr del 192.0.2.1/24 dev eth1
{% endhighlight %}

Start keepalived in both `J` and `K` using `sudo keepalived -lDn`. If you kill `J` or `J`'s Jool somehow (`sudo modprobe -r jool` for example), `K` should claim the addresses and start receiving `J`'s traffic in its stead. (after a small while.)

Notice that, if you want to modprobe jool back, you need to enable SS and restart joold right away, or the new instance will miss the advertise. You can later issue `jool --joold --advertise` manually (in `K`) if you forgot this.

## Configuration

### `jool`

1. `synch-enable`
2. `synch-disable`
3. `synch-flush-asap`
4. `synch-flush-deadline`
5. `synch-capacity`
6. `synch-max-payload`

### `netsocket.json`

This file configures the daemon's SS **network** socket. (The kernel socket does not need configuration for now.)

#### `multicast-address`

- Type: String (IPv4/v6 address)
- Default: None (Field is mandatory)

Address the SS traffic will be sent to.

You do not want to hinder your future ability to add more NAT64s to the cluster, so it is strongly recommended that you input a multicast address here.

#### `multicast-port`

- Type: String (port number or service name)
- Default: None (Field is mandatory)

TCP port where the SS traffic will be sent to.

#### `in interface`

- Type: String
- Default: NULL (kernel chooses an interface and address for you)

Address or interface to bind the socket in.

If `multicast-address` is IPv4, this should be one addresses from the interface where the SS traffic is expected to be received. If `multicast-address` is IPv6, this should be the name of the interface (eg. "eth0").

Though they are optional, it is strongly recommended that you define both `in interface` and `out interface` to ensure the SS traffic does not leak through other interfaces.

#### `out interface`

- Type: String
- Default: NULL (kernel chooses an interface and address for you)

If `multicast-address` is IPv4, this should be one addresses from the interface where the multicast traffic is expected to be sent. If `multicast-address` is IPv6, this should be the name of the interface (eg. "eth0").

Though they are optional, it is strongly recommended that you define both `in interface` and `out interface` to ensure the SS traffic does not leak through other interfaces.

#### `reuseaddr`

- Type: Integer
- Default: 0

Same as `SO_REUSEADDR`. From `man 7 socket`:

	SO_REUSEADDR
		Indicates that the rules used in validating addresses supplied
		in a bind(2) call should allow reuse of local addresses. For
		AF_INET sockets this means that a socket may bind, except when
		there is an active listening socket bound to the address. When
		the listening socket is bound to INADDR_ANY with a specific port
		then it is not possible to bind to this port for any local
		address. Argument is an integer boolean flag.

A rather more humane explanation can be found in [Stack Overflow](http://stackoverflow.com/questions/14388706):

	In other words, for multicast addresses `SO_REUSEADDR` behaves exactly
	as `SO_REUSEPORT` for unicast addresses.

	...

	Basically, `SO_REUSEPORT` allows you to bind an arbitrary number of
	sockets to exactly the same source address and port as long as all prior
	bound sockets also had `SO_REUSEPORT` set before they were bound. If the
	first socket that is bound to an address and port does not have
	`SO_REUSEPORT` set, no other socket can be bound to exactly the same
	address and port, regardless if this other socket has `SO_REUSEPORT` set
	or not, until the first socket releases its binding again.

You do not want a hanging joold to prevent future joolds from having access to the SS traffic, so there is likely no reason to ever turn this value off. Unless you have a specific reason to change this, you should **always** include this value, and **always** override the default.

#### `ttl`

- Type: Integer
- Default: 1

Same as `IP_MULTICAST_TTL`. From `man 7 ip`:

	IP_MULTICAST_TTL (since Linux 1.2)
		Set or read the time-to-live value of outgoing multicast packets
		for this socket. It is very important for multicast packets to
		set the smallest TTL possible. The default is 1 which means that
		multicast packets don't leave the local network unless the user
		program explicitly requests it. Argument is an integer.

## Persistent Daemon

