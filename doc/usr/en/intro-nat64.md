---
layout: documentation
title: Documentation - Introduction to NAT64
---

[Documentation](doc-index.html) > [Introduction](doc-index.html#introduction) > NAT64

# Introduction to IPv4/IPv6 Translation

## Index

1. [Introduction](#introduction)
2. [IPv4/IPv6 Translation](#ipv4ipv6-translation)
   1. [SIIT with EAM](#siit-with-eam)
   2. [SIIT (traditional)](#siit-traditional)
   3. [Stateful NAT64](#stateful-nat64)

## Introduction

This document provides a general introduction to SIIT and NAT64.

## IPv4/IPv6 Translation

SIIT (_Stateless IP/ICMP Translation_) and NAT64 ("NAT six four", not "NAT sixty-four") are technologies meant to communicate networking nodes which only speak [IPv4](http://en.wikipedia.org/wiki/IPv4) with nodes that only speak [IPv6](http://en.wikipedia.org/wiki/IPv6).

The idea is basically that of an "upgraded" [NAT](http://en.wikipedia.org/wiki/Network_address_translation); an "IPv4/IPv6 translator" not only replaces addresses and/or ports within packets, but also layer 3 headers.

- SIIT is the simpler form, and allows preconfigured 1-to-1 mappings between IPv4 addresses and IPv6 addresses.
- A _Stateful NAT64_ (or NAT64 for short) allows several IPv6 nodes to dynamically share few IPv4 addresses (useful when you're a victim of [IPv4 address exhaustion](http://en.wikipedia.org/wiki/IPv4_address_exhaustion)).

For historic reasons, sometimes we mess up and label SIIT as "Stateless NAT64". Because this expression does not seem to appear in any relevant standards, we consider it imprecise, despite the fact it makes some degree of sense. If possible, please try to suppress it.

An SIIT implementation mangles network headers and sometimes transport checksums. A Stateful NAT64 also mangles transport identifiers.

That's all, really. Keep reading for more detail and examples.

## SIIT with EAM

This is the easiest one to explain. Consider the following setup:

![Fig.1 - EAM sample network](images/network/eam.svg)

(_T_ stands for "Translating box".)

Assuming everyone's default gateway is _T_, how do you communicate _A_ (IPv6) with _V_ (IPv4)?

- You tell _T_, "The IPv4 address of _A_ should be 198.51.100.8, and the IPv6 address of _V_ should be 2001:db8:4::16".
- You tell _A_, "_V_'s address is 2001:db8:4::16".
- You tell _V_, "_A_'s address is 198.51.100.8".

The first one is accomplished by SIIT. The latter can be done via DNS.

This will happen:

![Fig.2 - EAM flow](images/flow/eam.svg)

The translator is "fooling" each node into thinking the other one can speak their language.

"EAM" stands for "Explicit Address Mapping", and is more versatile than simply binding arbitrary addresses to other arbitrary addresses. See the [EAM draft](https://tools.ietf.org/html/draft-anderson-v6ops-siit-eam-02) or [our summary of it](misc-eamt.html) for more information.

## SIIT (traditional)

The basic form of SIIT is more constrictive. As a consequence, we need to change the sample IPv6 network:

![Fig.3 - Vanilla sample network](images/network/vanilla.svg)

The idea is to simply remove a prefix while translating from IPv6 to IPv4, and append it in the other direction:

![Fig.4 - Vanilla flow](images/flow/vanilla.svg)

Of course, this means each node's IPv4 address has to be encoded inside its IPv6 address, which is a little annoying.

While this explanation might make it seem like "EAM" SIIT and "traditional" SIIT are different things, this is not the case. Implementations are expected to always try to translate an address based on the EAM table first, and if no mapping is found, fall back to append or remove the prefix. The separation was done here for illustrative purposes. You can find a concrete example of how "traditional" and "EAM" SIIT can be combined to fit a use case in [draft-v6ops-siit-dc](http://tools.ietf.org/html/draft-ietf-v6ops-siit-dc-00).

SIIT is defined by <a href="http://tools.ietf.org/html/rfc6145" target="_blank">RFC 6145</a>. The address translation hack has more ways to embed the IPv4 address not shown here, and is fully defined by <a href="http://tools.ietf.org/html/rfc6052" target="_blank">RFC 6052</a>. Whenever RFC 6052 is involved, it's usually convenient to also have a [DNS64](op-dns64.html) so users don't need to be aware of the prefix.

## Stateful NAT64

This mode is more akin to what people understand as "NAT". As such, allow me to remind you the big picture of how (stateful) NAT operates:

![Fig.5 - NAT sample network](images/network/nat.svg)

The idea is, the left network is called "Private" because it uses [addresses unavailable in the global Internet](http://en.wikipedia.org/wiki/Private_network). In order to make up for this, _NAT_ mangles packet addresses so outsiders think any traffic started by the private nodes was actually started by itself:

![Fig.6 - NAT flow](images/flow/nat.svg)

As a result, for outside purposes, nodes _A_ through _E_ are "sharing" _NAT_'s global address (or addresses).

While stateful NAT helps you economize IPv4 address, it comes with a price: _NAT_ has to remember which private node issued the packet to _V_, because _A_'s address cannot be found anywhere in _V_'s response. That's why it's called "stateful"; it creates address mappings dymanically and remembers them for a while. There are two things to keep ind mind here:

- Each mapping requires memory.
- _V_ cannot **start** a packet stream with _A_, again because _NAT_ **must** learn the mapping in the private-to-outside direction first (left to right).

Stateful NAT64 is pretty much the same. The only difference is that the "Private Network" is actually an IPv6 network:

![Fig.7 - Stateful network](images/network/stateful.svg)

And therefore,

![Fig.8 - Stateful flow](images/flow/stateful.svg)

Now, that's where the similarities with NAT end. You don't normally say the IPv6 network is "Private", because the whole point is that it should also be connected to the IPv6 Internet:

![Fig.9 - Stateful Internet](images/network/full.svg)

In this way, _A_ through _E_ are _IPv6-only_ nodes, but they have access to both Internets (the IPv6 one via router _R_, and the IPv4 one via _T_).

Stateful NAT64 is defined by <a href="http://tools.ietf.org/html/rfc6146" target="_blank">RFC 6146</a> and is most of the time coupled with [DNS64](op-dns64.html).

