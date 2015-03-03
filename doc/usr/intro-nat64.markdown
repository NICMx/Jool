---
layout: documentation
title: Documentation - Introduction to NAT64
---

[Documentation](doc-index.html) > [Introduction](doc-index.html#introduction) > NAT64

# Introduction to NAT64

## Index

1. [Introduction](#introduction)
2. [NAT64](#nat64)
   1. [Stateless NAT64 (with EAM)](#stateless-nat64-with-eam)
   2. [Stateless NAT64 (vanilla)](#stateless-nat64-vanilla)
   3. [Stateful NAT64](#stateful-nat64)

## Introduction

This document provides a general introduction to NAT64.

## NAT64

NAT64 ("NAT six four", not "NAT sixty-four") is a technology meant to communicate networking nodes which only speak [IPv4](http://en.wikipedia.org/wiki/IPv4) with nodes that only speak [IPv6](http://en.wikipedia.org/wiki/IPv6).

The idea is basically that of an "upgraded" [NAT](http://en.wikipedia.org/wiki/Network_address_translation); A NAT64 box not only replaces addresses and/or ports within packets, but also layer 3 headers.

Also, just like in NAT, There are two kinds of NAT64s:

- A _stateless NAT64_ is the simpler form, and allows preconfigured 1-to-1 mappings between IPv4 addresses and IPv6 addresses.
- A _stateful NAT64_ allows several IPv6 nodes to dynamically share few IPv4 addresses (useful when you're a victim of [IPv4 address exhaustion](http://en.wikipedia.org/wiki/IPv4_address_exhaustion)).

That's all, really. Keep reading for more detail and examples.

## Stateless NAT64 (with EAM)

This is the easiest one to explain. Consider the following setup:

![Fig.1 - EAM sample network](images/network/eam.svg)

Assuming everyone's default gateway is node _N_, how do you communicate _A_ (IPv6) with _V_ (IPv4)?

- You tell _N_, "The IPv4 address of _A_ should be 198.51.100.8, and the IPv4 address of _V_ should be 2001:db8:4::16".
- You tell _A_, "_V_'s address is 2001:db8:4::16".
- You tell _V_, "_A_'s address is 198.51.100.8".

The first one is accomplished by the NAT64. [The latter can be done via DNS](op-dns64.html).

This will happen:

![Fig.2 - EAM flow](images/flow/eam.svg)

The NAT64 is "fooling" each node into thinking the other one can speak their language.

"EAM" stands for "Explicit Address Mapping", and is more versatile than simply binding arbitrary addresses to other arbitrary addresses. See our [configuration documentation](usr-flags-eamt.html) or the [EAM draft](https://tools.ietf.org/html/draft-anderson-v6ops-siit-eam-02) for more information.

## Stateless NAT64 (vanilla)

The traditional form of stateless NAT64 is more constrictive. As a consequence, we need to change the sample IPv6 network:

![Fig.3 - Vanilla sample network](images/network/vanilla.svg)

The idea is to simply remove a prefix while translating from IPv6 to IPv4, and append it in the other direction:

![Fig.4 - Vanilla flow](images/flow/vanilla.svg)

Of course, this means each node's IPv4 address has to be encoded inside its IPv6 address, which is a little annoying.

While this explanation might make it seem like "EAM Stateless NAT64" and traditional Stateless NAT64 are different things, this is not the case. Implementations are expected to always try to translate an address based on the EAM table first, and if no mapping is found, fall back to use the "vanilla" prefix. The separation was done here for illustrative purposes.

Stateless NAT64 is defined by <a href="http://tools.ietf.org/html/rfc6145" target="_blank">RFC 6145</a>.

## Stateful NAT64

This mode is more akin to what people understand as "NAT". As such, allow me to remind you the big picture of how (stateful) NAT operates:

![Fig.5 - NAT sample network](images/network/nat.svg)

The idea is, the left network is called "Private" because it uses [addresses unavailable in the global Internet](http://en.wikipedia.org/wiki/Private_network). In order to make up for this, _N_ mangles packet addresses so outsiders think any traffic started by the private nodes was actually started by itself:

![Fig.6 - NAT flow](images/flow/nat.svg)

As a result, for outside purposes, nodes _A_ through _E_ are "sharing" _N_'s global address (or addresses).

While stateful NAT helps you economize IPv4 address, it comes with a price: _N_ has to remember which private node issued the packet to _V_, because _A_'s address cannot be found anywhere in _V_'s response. That's why it's called "stateful"; it creates address mappings dymanically and remembers them for a while. There are two things to keep ind mind here:

- Each mapping requires memory.
- _V_ cannot **start** a packet stream with _A_, again because _N_ **must** learn the mapping in the private-to-outside direction first (left to right).

Stateful NAT64 is pretty much the same. The only difference is that the "Private Network" is actually an IPv6 network:

![Fig.7 - Stateful network](images/network/stateful.svg)

And therefore,

![Fig.8 - Stateful flow](images/flow/stateful.svg)

Now, that's where the similarities with NAT end. You don't normally say the IPv6 network is "Private", because the whole point is that it should also be connected to the IPv6 Internet:

![Fig.9 - Stateful Internet](images/network/full.svg)

In this way, _A_ through _D_ are _IPv6-only_ nodes, but they have access to both Internets (the IPv6 one via router _R_, and the IPv4 one via _N_).

Stateful NAT64 is defined by <a href="http://tools.ietf.org/html/rfc6146" target="_blank">RFC 6146</a>.

