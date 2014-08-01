---
layout: documentation
title: Documentation - Introduction to NAT64
---

# Introduction to NAT64

## Index

1. [Introduction](#introduction)
2. [Background](#background)
   1. [IPv4](#ipv4)
   2. [IPv6](#ipv6)
3. [Transition mechanisms](#transition-mechanisms)
4. [NAT64](#nat64)
   1. [Stateless NAT64](#stateless-nat64)
   2. [Stateful NAT64](#stateful-nat64)
5. [Jool](#jool)
   1. [Considerations](#considerations)

## Introduction

This document intends to provide a general introduction of NAT64 and its background.

It's succinct on purpose. If you need more context, there's nothing wrong with the Wikipedia articles:

* <a href="http://en.wikipedia.org/wiki/IPv4" target="_blank">IPv4</a>
* <a href="http://en.wikipedia.org/wiki/IPv6" target="_blank">IPv6</a>
* <a href="http://en.wikipedia.org/wiki/IPv4_address_exhaustion" target="_blank">IPv4 address exhaustion</a>
* <a href="http://en.wikipedia.org/wiki/IPv6_transition_mechanisms" target="_blank">IPv6 transition mechanisms</a>
* <a href="http://en.wikipedia.org/wiki/NAT64" target="_blank">NAT64</a>

## Background

### IPv4

Each electronic device (node) connected to a network needs at least one identifier (address) that uniquely represents it. This address is a four bytes long integer, so in theory there's a limit of 4,294,967,296 possible nodes in the Internet.

While that might or might not still be a problem, several issues have aggravated their depletion: The growth of the Internet population, the reserved address blocks and inefficient address assignment are examples of factors which have inspired the introduction of new technologies such as NAT (Network Address Translation) and IPv6.

Representing addresses as average integers is annoying, so they are usually expressed in dotted decimal format (e.g. "192.0.2.1"), where each number represents one of the four bytes.

### IPv6

Internet Protocol version 6 (IPv6) is the latest revision of the Internet Protocol (IP). It was developed by the Internet Engineering Task Force (IETF) to deal with the long-anticipated problem of IPv4 address exhaustion, and uses 128-bit addresses, allowing 2<sup>128</sup> (or more than 7.9 x 10<sup>28</sup> times as many as IPv4) nodes to coexist at a time.

IPv6 addresses are represented as eight groups of four hexadecimal digits separated by colons (for example "2001:0db8:85a3:0042:1000:8a2e:0370:7334"). If your address has zero groups, they can be obviated (2001:db8:: is the same as 2001:0db8:0000:0000:0000:0000:0000:0000).

## Transition mechanisms

Because a worldwide switch from IPv4 to IPv6 cannot be done in the blink of an eye, several technologies have been devised to help IPv4 networks coexist with IPv6 ones. Some transition mechanisms are

* Dual stacking
* DS-Lite
* IPv4 tunneling
* IVI
* NAT64

Comparing them is outside of the scope of this document. We'll just jump straight to NAT64 instead:

## NAT64

A NAT64 ("NAT six four", not "NAT sixty-four") is a node which translates network headers from IPv4 to IPv6 and vice-versa.

You might think that the nodes from either side of the following diagram are people literally speaking different languages, and they interact with each other by having the mediator node translate what they're saying. You might alternatively think that the middle node is fooling the IPv6 nodes into thinking that the IPv4 nodes are also IPv6, and viceversa. Either way, if either of the packets displayed is a NAT64'd version of the other one, you normally expect them to have the same payload:

![Fig.1 - Headers morphing](images/intro-nat64.svg)

There are two kinds of NAT64s: Stateless and stateful.

### Stateless NAT64

A "stateless" NAT64 is one in which there is a strong algorithmic relationship between each IPv6 address and each IPv4 address (i.e. a 1-to-1 mapping is possible).

In the simplest case, you can obtain an IPv6 address simply by appending a prefix to an IPv4 address:

	64:ff9b:: + 10.1.2.3 = 64:ff9b::10.1.2.3 = 64:ff9b::0a01:0203

Here's an example:

![Fig.2 - Stateless example](images/intro-stateless.svg)

Because such a transformation is possible, the NAT64 needs little memory (Hence the name, "stateless"). All you need to configure is the prefixes the translator is supposed to add and remove, and fix your routing in such a way that traffic meant to be translated is sent to the NAT64. Stateless NAT64s are simple, light and transparent. If you need one of these, you might want to head over to <a href="http://www.litech.org/tayga/" target="_blank">TAYGA</a>.

> A word on TAYGA:
> 
> TAYGA tends to confuse my readers, because it doesn't seem to behave the way I've described here, at least not by default.
> 
> What happens is, my explanation above tells you about _pure_ stateless NAT64, and TAYGA builds on top of that by letting you build translation tables. That is, it lets you map specific IPv6 addresses to specific IPv4 addresses, which removes the constraint that forces you to encapsulate the latter inside the former. It's not really a violation of the RFC (I guess), but watch out for it.

Stateless NAT64 is defined by <a href="http://tools.ietf.org/html/rfc6145" target="_blank">RFC 6145</a>.

### Stateful NAT64

On the other hand, when you don't have an IPv4 address for every node you want to publish to the IPv4 side, you might be forced to use a "stateful" NAT64 instead.

A stateful NAT64 has a pool of IPv4 addresses to work with. When an IPv6 packet arrives, the NAT64 picks an IPv4 address to mask the IPv6 one with and remembers the mapping. When the response to the packet arrives, it looks for the mapping in its database and uses it to figure out which IPv6 node the packet corresponds to. There is a strong algorithmic relationship between the IPv4 address and the IPv6 one, but only in one direction:

![Fig.3 - Stateful example](images/intro-stateful.svg)

Because the NAT64 gets to decide which IPv4 address to use, several IPv6 nodes can share an IPv4 addresses.

Though you're better off knowing what you're doing while configuring this setup, the whole ordeal is almost completely transparent for the nodes themselves: The IPv6 nodes see the IPv4 ones as if they're just an ordinary IPv6 network with a particular prefix, while the IPv4 nodes see a normal NAT.

Stateful NAT64 is defined by <a href="http://tools.ietf.org/html/rfc6146" target="_blank">RFC 6146</a>.

## Jool

Jool is an Open Source implementation of a Stateful NAT64 on Linux. It is intended to comply perfectly with the RFC. As of now (2014-07-30), we're one feature away from the goal:

1. <a href="https://github.com/NICMx/NAT64/issues/41" target="_blank">Filtering policies</a>.

We're supposed to support Linux kernels 3.0.0 and up. While most of the development time has been spent experimenting on Ubuntu 12.04 using kernel 3.2.0-63-generic-pae, we've performed a healthy amount of formal testing on Jool 3.1.5 in the following variants:

| Distribution | Kernels |
| -------------|---------|
| CentOS | 3.10 |
| Debian 7 | 3.2 |
| Red Hat | 3.10 |
| SuSE | 3.0.101-0.35-default |
| Ubuntu 12.04 | 3.1.10-030110-generic, 3.2.60-030260-generic |
| Ubuntu 12.10 | 3.3.8-030308-generic, 3.4.94-030494-generic, 3.5.7-03050733-generic |
| Ubuntu 13.04 | 3.6.11-030611-generic, 3.7.10-030710-generic, 3.8.13-03081323-generic |
| Ubuntu 13.10 | 3.9.11-030911-generic, 3.10.44-031044-generic, 3.11.10-03111011-generic |
| Ubuntu 14.04 | 3.12.22-031222-generic, 3.13.11-03131103-generic |
| Ubuntu 14.10 | 3.14.8-031408-generic, 3.15.1-031501-generic |

### Considerations

Our missing feature (see above) means that you cannot firewall your packets being translated. If you need to filter, you're better off placing another node next to the NAT64 to do the task.

Here's a [list of oddities](quirks.html) regarding Jool's design that people might want to debate.

And that's really all you need to know to jump to the [tutorial](tutorial1.html).

