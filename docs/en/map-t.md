---
language: en
layout: default
category: Documentation
title: MAP-T
---

# MAP-T

## Index

1. Introduction
2. Thought Process
3. The MAP Address Format

## Introduction

This document is a layman's (but exhaustive) explanation of MAP-T. It is intended to serve as a replacement for RFC 7599, or at least, as preparatory reading for it. I'm assuming you've already consumed the [general introduction to the topic](intro-xlat.html#map-t), so you know what you're getting into.

## Thought Process

In order to define your MAP-T network, you first need a general idea of how you're going to distribute your available public transport addresses.

Suppose you have the entirety of block 192.0.2.0/24 to distribute among your CEs. Suppose, as well, that you have 5000 customers.

Considering that the size of your IPv4 address pool is 256 (because of "/24"), with a simple division (ceiling of customers divided by pool size) you will conclude that you need to fit 20 customers per address.

Therefore, each address needs to be divided into 20 "Sets" of ports. (But MAP-T likes powers of two, so we will round that up to 32.) We will assing each set to a different customer, and leftovers will be reserved for a future growth of our customer pool or whatever.

> ![Warning!](../images/warning.svg) The following paragraph assumes `a = 0` and `m = 11`. Don't worry about this for now; `a` and `m` will be explained later.

So, we will divide each address into 32 sets of 2048 ports each (65536 / 32). The first set consists of ports 0-2047, the second set has 2048-4095, the third set has 4096-6143, and so on. The last set has 63488-65535.

With that in mind, I would like to introduce the notion of _Embedded Address bits_ ("EA-bits"). It's basically a CE identifier. (In fact, I wish it were called that, but I don't write the rules.) Each CE has a different one. It's composed of a concatenation of the suffix of the IPv4 address that has been assigned to the CE, as well as the identifier of its Port Set. In our example, we would need 8 bits for the suffix and 5 bits for the _Port Set IDentifier_ (PSID):

![Diagram: EA-bits](../images/mapt/ea-bits.svg)

> ![Note!](../images/bulb.svg) The general introduction used to refer to EA-bits as "slice ID."

Let's visualize all of that:

![Network: EA-bits distribution](../images/mapt/distribution.svg)

Once you've designed your own version of that, you're ready to start assigning IPv6 prefixes to the CEs.

## The MAP Address Format

Remember when I [lied](intro-xlat.html#mapt)? Well, here's the full IPv6 address format defined by the MAP standard:

![Diagram: MAP Address Format](../images/mapt/map-addr-format.svg)

The addresses that are supposed to follow this structure are all "assigned" to the CEs. (In their CE configuration, not their interface configuration.)

<!-- ![Note!](../images/bulb.svg)  Personally, I wish the MAP Address Format were called the "CE Address Format." -->

Here's an explanation of every field:

### End-user IPv6 Prefix

The CE's unique prefix. All the traffic headed towards this prefix needs to be routed by the network towards the corresponding CE. It is interesting to note that this is actually the only part of the address that matters; everything else is clutter.

### Rule IPv6 Prefix

This is just an arbitrary prefix owned by your organization, reserved for CE usage. (It is generally assumed that all CEs have the same prefix, though I don't think there's anything stopping you from breaking this convention.)

Way I see it, if your organization is assigned 2001:db8::/64, you might for example assign something like 2001:db8:0:0:4464::/80 as your "Rule IPv6 prefix." Each of your CEs needs to pick a subprefix from this pool to operate.

### EA-bits

The CE's unique identifier. It contains both the IPv4 address suffix and the PSID. See [Thought Process](#thought-process) above.

<!--
This is what the general introduction referred to as "slice ID." You can also think of it as a "CE identifier;" Every CE has a different one.

Depending on how many IPv4 addresses you have, and how many you're willing to assign to each CE, there are three different MAP-T scenarios:

1. You have less IPv4 addresses than CEs, so your CEs will have to share IPv4 addresses.
2. You have the same number of IPv4 addresses than CEs, so each CE will have one IPv4 address.
3. You have more IPv4 addresses than CEs, thus you can assign more than one IPv4 address to each CE.

> ![Note!](../images/bulb.svg) The first is actually the only one I described in the general introduction. (In my opinion, it's the one that makes the most sense. Not that the others don't.)

The reason why I'm explaining this is to segue into the notion that the CE identifier is not an accidental number you can arbitrarily assign, but rather, the concatenation of two crucial pieces of CE configuration you have to design: The _Full or partial IPv4 address_ (which identifies the IPv4 address assigned to the CE) and the _Port Set IDentifier_ (which, needless to say, identifies the Port Set assigned to the CE). They are explained thus:
-->

### Subnet ID

This is a big fat hilariously overnamed nothing.

Perhaps this field makes more sense in the context of encapsulation (as MAP-T is a sibling technology to MAP-E, ie. "MAP-T but with Encapsulation instead of Translation"), but neither of the MAP RFCs have much to say about it.

As it stands, the _Subnet ID_ is just an optional block of padding (zeroes) meant to ensure that the _Interface ID_ starts in bit number 64. (Which, considering the _Interface ID_ starts with padding, itself doesn't really seem to serve any purpose.)

### Interface ID

I'm guessing the length of IPv6 addresses left the MAP designers with too many surplus bits, and they decided to grant pointless purpose to the leftovers instead of leaving them in reserved status.

The Interface ID is just redundant data. It's so unnecesary, in fact, that the _End-user IPv6 Prefix_ is allowed to length up to 128 bits, an in order to accomplish this, it unapologetically overrides the _Interface ID_ bits. (So, even if I stated in the diagram that the _Interface ID_ lengths 64 bits, some of its leftmost bits might be chopped off.)

My guess is that the _Interface ID_ only exists so that, given a MAP address, you can visually locate the IPv4 address and the PSID without having to analyze the EA-bits. (Assuming the former haven't been chopped off.) (And you'll still need to mentally convert the IPv4 address from hex to decimal.)

> ![Note!](../images/bulb.svg) Because they can be truncated, Jool doesn't do anything with any of the _Interface ID_'s subfields. They simply exist. (Or not.)

Without further ado, the Interface ID is composed of three subfields:

### 16 bits

Just padding; sixteen zeroes with no meaning.

### IPv4 address

Basically the full IPv4 address from which we extracted the EA-bits's IPv4 address suffix subfield.

### PSID

The PSID again, right-aligned and left-padded with zeroes for your viewing convenience. (I guess.)

## All right, let's configure our damn CEs already

WIP

