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
5. [Configuration](#configuration)
	1. [Daemon](#daemon)
	2. [Load Balancer](#load-balancer)
	3. [Kernel Module](#kernel-module)

## Introduction

The fact that stock NAT64 is stateful makes redundancy difficult. You can't simply configure two independent NAT64s and expect that one will serve as a backup for the other should the latter fall.

> Well, you can in reality, but users will notice that they need to re-establish all their lasting connections during a failure since the new NAT64 needs to recreate all the [dynamic mappings](bib.html) (and their sessions) that the old NAT64 lost.

Since version 3.5, Jool ships with a daemon that allows constant synchronization of sessions across Jool instances so you can work around this limitation. The purpose of this document is to explain and exemplify its usage.

Session Synchronization (hereby abbreviated as "SS") applies to NAT64 Jool only. SIIT stores no state, and therefore it has no difficulties regarding failover clustering.

## Sample Network

Fig

Nodes `J`, `K` and `L` will be Stateful NAT64s. Their configuration will be only slightly different, and any number of extra backup NAT64s can be appended by replicating similar configuration through additional nodes. You intend to have at least two of these nodes.

Network `10.0.0.0/24` is a private network where the sessions will be advertised as the NAT64s serve traffic through their other interfaces. You want this network to be dedicated because sessions are confidential information to some extent, and as a result you don't want this information to leak elsewhere.

## Traffic Flow Explanation

First, let's analyze what happens when you create multiple Jool instances but do not enable SS:

### Session Synchronization Disabled

IPv4 node `n4` will interact with IPv6 node `n6` via `J`. As is natural of NAT64, `J` will store a mapping (and a session) to service this connection:

FigFig

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

Each machine hosting a NAT64 will also hold a daemon that will bridge SS traffic between the private network and its Jool instance. This daemon is named `joold`.

Why is the daemon necessary? because kernel modules cannot open IP sockets; at least not in a reliable and scalable manner.

Synchronizing sessions is _all_ the daemon does; the traffic redirection part is delegated to other protocols (TODO I don't think this redirection thing is explained too well above). [Keepalived](http://www.keepalived.org/) is the implementation that takes care of this in the sample configuration below, but any other load balancer should also get the job done.

In this proposed/inauguratory implementation, SS traffic is distributed through an IPv4 or IPv6 unencrypted TCP connection. You might want to cast votes on the issue tracker or propose code if you favor some other solution.

It is also important to note that SS is relatively resource-intensive; its traffic is not only _extra_ traffic, but it must also do two full U-turns to userspace before reaching its destination:

FigFigFigFigFigFigFig

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

## Configuration

### Daemon

### Load Balancer

### Kernel module

