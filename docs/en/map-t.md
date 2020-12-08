---
language: en
layout: default
category: Documentation
title: MAP-T
---

# MAP-T

## Index

1. [Introduction](#introduction)
2. [Foreword](#foreword)
2. [Thought Process](#thought-process)
3. [The MAP Address Format](#the-map-address-format)
	1. [End-user IPv6 Prefix](#end-user-ipv6-prefix)
	2. [Rule IPv6 Prefix](#rule-ipv6-prefix)
	3. [EA-bits](#ea-bits)
	4. [Subnet ID](#subnet-id)
	5. [Interface ID](#interface-id)
	6. [16 bits](#16-bits)
	7. [IPv4 address](#ipv4-address)
	8. [PSID](#psid)
4. [CE Configuration](#ce-configuration)
5. [CE Behavior](#ce-behavior)
6. [BR Configuration](#br-configuration)
7. [BR Behavior](#br-behavior)
8. [Additional Configuration](#additional-configuration)
	1. [The `a`, `k` and `m` configuration variables](#the-a-k-and-m-configuration-variables)
	2. [FMR on the CE](#fmr-on-the-ce)

## Introduction

This document is a layman's (but exhaustive) slightly sardonic explanation of MAP-T. It is intended to serve as a replacement for RFCs 7597 and 7599, or at least, as preparatory reading for them. **I'm assuming you've already consumed the [general introduction to the topic](intro-xlat.html#map-t), so you know what you're getting into.**

> ![Warning!](../images/warning.svg) Please be aware that Jool does not yet implement MAP-T. (Support will be added in version 4.2.0.)
> 
> In any case, this particular document does not deal with Jool in any way. (That's the [tutorial](run-mapt.html)'s job.)

Expected background knowledge:

- IPv4 addresses
- IPv6 addresses
- Hexadecimal and binary numbers

## Foreword

The MAP RFCs argue that, depending on how many IPv4 addresses you have, and how many you're willing to assign to each CE, there are three different MAP-T scenarios:

1. You have less IPv4 addresses than CEs, so your CEs will have to share IPv4 addresses.
2. You have the same number of IPv4 addresses as CEs, so each CE will have one IPv4 address.
3. You have more IPv4 addresses than CEs, thus you can assign more than one IPv4 address to each CE.

In my opinion, the first scenario is the only one that truly makes sense. (If you have that many IPv4 addresses, I think SIIT-DC-2xlat would be a simpler alternative to MAP-T.) However, I will walk you through all three of them, in the hopes that some variety migh facilitate the "aha!" moment. (TODO: I still haven't done scenarios 2 nor 3.)

<!--
> ![Note!](../images/bulb.svg) The first is actually the only one I described in the general introduction. (In my opinion, it's the one that makes the most sense. Not that the others don't.)

The reason why I'm explaining this is to segue into the notion that the CE identifier is not an accidental number you can arbitrarily assign, but rather, the concatenation of two crucial pieces of CE configuration you have to design: The _Full or partial IPv4 address_ (which identifies the IPv4 address assigned to the CE) and the _Port Set IDentifier_ (which, needless to say, identifies the Port Set assigned to the CE). They are explained thus:
-->

First, let's take a look at scenario 1.

## Thought Process

In order to define your MAP-T network, you first need a general idea of how you're going to distribute your available public transport addresses.

Suppose you have the entirety of block <span class="addr4">192.0.2.0/24</span> to distribute among your CEs. Suppose, as well, that you have 5000 customers.

Let's define some variables:

- _r_ = Length of the IPv4 prefix (Defined by RFC 7597)
- _p_ = Length of the IPv4 suffix (Defined by RFC 7597)
- _a<sub>4</sub>_ = Number of available IPv4 "a"ddresses
- _c_ = Total "c"ustomers
- _c<sub>4</sub>_ = "C"ustomers per IPv"4" address

Yes, I'm also very upset by the RFC's choices.

In our example,

<style type="text/css">
	.equations {
		display: block;
		margin-left: auto;
		margin-right: auto;
	}
</style>

<img src="../images/mapt/equations1.png" alt="Equations: 1" class="equations" />

> ![Note](../images/bulb.svg) Not sure if I should be explaining this, but the "&#8968;&#8969;" operator means [_ceiling_](https://en.wikipedia.org/wiki/Floor_and_ceiling_functions).

As you can see, each address needs to be divided into 20 "Sets" of ports. (But MAP-T likes powers of two, so we'll have to round that up to 32.) We will assign each set to a different customer. (And leftovers will be reserved for a future growth of our customer pool or whatever.)

- _S_ = Number of "s"ets per IPv4 address
- _P_ = Number of "P"orts per set

<img src="../images/mapt/equations2.png" alt="Equations: 2" class="equations" />

So, we will divide each address into 32 sets of 2048 ports each.

> ![Warning!](../images/warning.svg) The following is an oversimplification that assumes `a = 0` and `m = 11`. Don't worry about this for now; `a` and `m` will be explained later.
> 
> Also, take heed of the upcoming multicharacter variable. We're dropping the formal pretenses now.

The first port of set _PSID_ is _P_ * _PSID_, and its last port is _P_ * (_PSID_ + 1) - 1. (Where _PSID_ = { 0, 1, 2, 3, ..., _S_ - 1 }.)

In english:

| Port Set #<br />(aka. "Port Set Identifier," "PSID") | First Port | Last Port |
|--------------------|------------|-----------|
| 0                  | 0          | 2047      |
| 1                  | 2048       | 4095      |
| 2                  | 4096       | 6143      |
| 3                  | 6144       | 8191      |
| ...                | ...        | ...       |
| 30                 | 61440      | 63487     |
| 31                 | 63488      | 65535     |

With that in mind, I would like to introduce the notion of _Embedded Address bits_ ("EA-bits"). It's basically a CE identifier. (In fact, I wish it were called that, but I don't make the rules.) It's composed of a concatenation of the suffix of the IPv4 address that has been assigned to the CE, as well as the identifier of its Port Set. We need `p` bits for the suffix, and <code>q = log<sub>2</sub>(S)</code> bits for the _PSID_. In our example, that would be `p = 8` and `q = 5`:

![Diagram: EA-bits](../images/mapt/ea-bits.svg)

As my wishful name implies, each CE has a unique EA-bits number.

> ![Note!](../images/bulb.svg) The general introduction used to refer to EA-bits as "slice ID."

> ![Note!](../images/bulb.svg) Only scenario 1 includes PSID. Port Sets only need to exist if the IPv4 addresses are being shared.

Let's visualize all of that. Please don't stop staring at this picture until you've understood the relationship between each CE's (hexadecimal) number and its assigned IPv4 address and (decimal) PSID:

![Network: EA-bits distribution](../images/mapt/distribution.svg)

> ![Warning!](../images/warning.svg) The RFCs define a rather important notion called "MAP domain," whose meaning is unfortunately significantly inconsistent across the specification. (Probably as a result of its evolution as the documents were written.)
> 
> For the purposes of this documentation, I've decided to go with the meaning that makes the most sense to me:
> 
> The diagram pictured above represents exactly one MAP domain. It's a group of MAP devices (CEs and BR) that share a common essential configuration known as the _Basic Mapping Rule_ (BMR).
> 
> Stick to the diagram for now; I will properly define the BMR later.

Once you've designed your own version of that, you're ready to start assigning IPv6 prefixes to the CEs.

## The MAP Address Format

Remember when I [lied](intro-xlat.html#map-t)? Well, here's the full IPv6 address format defined by the MAP proposed standard:

![Diagram: MAP Address Format](../images/mapt/map-addr-format.svg)

Though these are part of the CE configuration, they are actually used to mask the IPv4 island clients. (The address you will assign to the CE's IPv6-facing interface is a separate--and completely normal--IPv6 address.)

There's a fair bit of information encoded in the MAP address, which might help you understand and troubleshoot your network. Therefore, here's an explanation of every field:

### End-user IPv6 Prefix

The CE's unique prefix. All the traffic headed towards this prefix needs to be routed by the network towards the corresponding CE. It is interesting to note that, unless you're on scenario 3, this is actually the only technically meaningful part of the address; everything else is essentially cosmetics.

### Rule IPv6 Prefix

This is just an arbitrary prefix owned by your organization, reserved for CE usage. (All CEs sharing a common MAP domain will have the same Rule IPv6 Prefix.)

Way I see it, if your organization owns 2001:db8::/32, you might for example assign something like <span class="r6p">2001:db8:ce::/51</span> as your "Rule IPv6 prefix." Each of your CEs would need to pick a subprefix (ie. the [End-user IPv6 Prefix](#end-user-ipv6-prefix)) from <span class="r6p">2001:db8:ce::/51</span> to operate.

(These are just examples. Both the Rule IPv6 Prefix and the End-user IPv6 Prefix are technically allowed to span anywhere between 0 and 128 bits, so you can pick lengths that make more sense for your network.)

### EA-bits

The CE's unique identifier. (See [Thought Process](#thought-process) for the rundown.)

In scenario 1, EA-bits is actually two subfields glued together: the IPv4 address suffix and the PSID. In the other scenarios, EA-bits only contains the IPv4 address suffix.

This field is allowed to length anywhere between 0 to 48 bits. (32 bits for a full IPv4 address plus 16 for an entire port as PSID.)

### Subnet ID

The trailing bits required to assemble a full IPv4 address in scenario 3.

(This field only exists in scenario 3, so ignore it for now.)

### Interface ID

I'm guessing the length of IPv6 addresses left the MAP designers with too many surplus bits, and they decided to grant pointless purpose to the leftovers instead of leaving them in reserved status.

The _Interface ID_ is just redundant data. It's so unnecesary, in fact, that the _End-user IPv6 Prefix_ is allowed to length up to 128 bits, and in order to accomplish this, it unapologetically overrides the _Interface ID_ bits. (So, even if I stated in the diagram that the _Interface ID_ lengths 64 bits, some of its leftmost bits might be chopped off.)

My guess is that this field only exists so that, given a MAP address, you can visually locate the CE's public IPv4 address and PSID without having to analyze the EA-bits. (Assuming the former haven't been chopped off.) (And you'll still need to mentally convert the IPv4 address from hex to decimal.)

> ![Note!](../images/bulb.svg) Because they can be truncated, Jool doesn't do anything with any of the _Interface ID_'s subfields. They simply exist. (Or not.)

Without further ado, the Interface ID is composed of three subfields:

### 16 bits

Just padding; sixteen zeroes with no meaning.

### IPv4 address

Basically the full IPv4 address from which we extracted the EA-bits's IPv4 address suffix subfield.

It's also the public side address of the CE's NAPT.

### PSID

The CE's PSID again, right-aligned and left-padded with zeroes for your viewing convenience. (I guess.)

## CE Configuration

<style type="text/css">
	.footnote { font-size: 40%; }
</style>

> ![Note!](../images/bulb.svg) Please note that, in this context, "CE" is used to refer to the translator mechanism exclusively (ie. Jool). The NAPT is assumed to be a separate tool, configured independently.

In addition to usually requiring a NAPT to really make sense, a formal minimal CE configuration contains

<!-- TODO delete the "footnote" class? -->

1. [The End-user IPv6 Prefix](#end-user-ipv6-prefix)
2. A _Basic Mapping Rule_ (BMR)
3. A _Default Mapping Rule_ (DMR)

(More configuration parameters are offered by the standards, but we'll get to them later.)

CEs sharing a MAP domain will always have the same BMR, and usually the same DMR too. The _End-user IPv6 prefix_ is the only important configuration-wise distinction between them.

For some reason, the RFCs insist that "Mapping Rules" are always triplets of the following form:

	{
		<IPv6 Prefix>,
		<IPv4 Prefix>,
		<EA-bits length>
	}

This is not really true, but we'll play along for now.

Let's define those Mapping Rules:

### BMR

> ![Warning!](../images/warning.svg) Because the definition of the BMR is intrinsically tied to the concept of a "MAP domain," the BMR is also inconsistent across the RFCs. Once again, the definition presented here is my preferred one.

The _Basic Mapping Rule_ is a MAP domain's common MAP address configuration. Basically, this field is the essential piece of configuration that allows the translator to assemble [MAP addresses](#the-map-address-format) out of IPv4 addresses, and viceversa.

It refers specifically to addresses that will be governed by the [MAP address format](#the-map-address-format), not the [RFC 6052 address format](#dmr). Again, the BMR defines the base MAP address configuration that all CEs share, while the _End-user IPv6 prefix_ describes the additional MAP address specifics that belong to one particular CE.

Here's what each of the triplet fields stand for in the BMR:

	{
		<Rule IPv6 Prefix>,
		<IPv4 prefix reserved for CEs>,
		<EA-bits length>
	}

The "Rule IPv6 Prefix" is the same one defined [above](#rule-ipv6-prefix). The "IPv4 prefix reserved for CEs" is exactly what it sounds like (<span class="addr4">192.0.2.0/24</span> in the [example](#thought-process)). The "EA-bits length" is the total length (in bits) of the [EA-bits](#ea-bits) field.

So what does this do? Well, the suffix length of the _IPv4 prefix reserved for CEs_ (`p`, as defined [above](#thought-process)) and the _EA-bits length_ (`o`) describes the structure of the [EA-bits](#thought-process), and the _Rule IPv6 Prefix_ length describes their [offset](#the-map-address-format). If we define `r` as the length of the _IPv4 prefix reserved for CEs_,

- If `o + r > 32`, we're dealing with scenario 1. (`q > 0`)
- If `o + r = 32`, we're dealing with scenario 2. (`q = 0`)
- If `o + r < 32`, we're dealing with scenario 3. (`q = 0`)

In our example, the BMR would be

<style type="text/css">
	.ebl { color: #f95;  }
</style>

<pre><code>{
	<span class="r6p">2001:db8:ce::/51</span>,
	<span class="addr4">192.0.2.0/24</span>,
	<span class="ebl">13</span>
}</code></pre>

Which, in turn, will yield MAP Addresses that have the following form:

![Diagram: MAP Address Example](../images/mapt/map-addr-example.svg)

Again, for context: These address will represent devices on the IPv4 customer islands. (ie. Behind the CEs.)

### DMR

_Default Mapping Rule_ is just a fancy name for pool6. It's the "default" prefix that should be added to an outbound destination address so the packet is routed by the IPv6 network towards the _BR_ (and therefore, towards the IPv4 Internet). It has the following form:

	{
		<pool6>,
		<unused>,
		<unused>
	}

Yes, defining this as a "Mapping Rule" triplet is a stretch. Code-wise, it doesn't even make sense to implement it as one.

In our example, the DMR would be

<pre><code>{
	<span class="wkp">64:ff9b::/96</span>,
	&lt;unused&gt;,
	&lt;unused&gt;
}</code></pre>

Again: Addresses masked with the DMR will represent devices on the IPv4 Internet. (ie. Behind the BR.)

## CE Behavior

<style type="text/css">
	.r6p     { color: #0055d4; }
	.eabits  { color: #595959; background-color: #f95; }
	.addr4   { color: #668000; }
	.suffix4 { color: #595959; background-color: #ffe680; }
	.psid    { color: #595959; background-color: #ff5555; }
	.wkp     { color: #d40000; }
</style>

When one of the CE's clients makes an outbound request, the CE uses the BMR to translate the source address, and the DMR to translate the destination address.

![Packet flow: CE outbound](../images/mapt/flow-ce-outbound.svg)

Here's the breakdown:

- [<span class="r6p">Rule IPv6 Prefix</span>](#rule-ipv6-prefix)
- [<span class="eabits">EA-bits</span>](#ea-bits) (<span class="eabits">41</span><sub>16</sub> = <span class="suffix4">00000010</span><span class="psid">00001</span><sub>2</sub>)
- [<span class="addr4">IPv4 prefix</span>](#bmr)
- [<span class="suffix4">IPv4 suffix</span>](#ea-bits)
- [<span class="psid">PSID</span>](#psid)
- [<span class="wkp">DMR</span>](#dmr)
- The last 3 bits of the _End-user IPv6 Prefix_ and the 13 bits of the <span class="eabits">EA-bits</span> have completely overridden the [16 bits](#16-bits) field.

The opposite happens in the other direction:

![Packet flow: CE inbound](../images/mapt/flow-ce-inbound.svg)

## BR Configuration

The BR only needs two things:

- A _Forwarding Mapping Rule_ (FMR) table
- The _Default Mapping Rule_ (DMR)

The FMR table is a bunch of BMRs. One BMR per connected MAP domain.

In our example, the FMR would only have one entry:

| IPv6 Prefix          | IPv4 Prefix  | EA-bits length |
|----------------------|--------------|----------------|
| 2001:db8:ce::/51     | 192.0.2.0/24 | 13             |

The DMR is, once again, pool6.

	{
		64:ff9b::/96,
		<unused>,
		<unused>
	}

## BR Behavior

![Packet flow: BR outbound](../images/mapt/flow-br-outbound.svg)

Source is translated by FMR, destination by DMR.

![Packet flow: BR inbound](../images/mapt/flow-br-inbound.svg)

Source is translated by DMR, destination by FMR.

## Additional Configuration

If you're curious to get some hands-on experience, by now you should have the fundamentals required to know what you're doing if you [set up your own MAP-T scenario 1 environment with Jool](run-mapt.html).

Additional bells and whistles follow:

### The `a`, `k` and `m` configuration variables

Ok, so this is a bit of a doozy because the Linux kernel is not terribly well-equipped to deal with these variables, but I'll explain them nonetheless.

If you were paying close attention, you might have noticed in the example above that, even though we happily assembled 32 port sets, one of them is actually unusable: Port Set zero. Why? Because it contains the "taboo" ports: 0-1023.

To me, personally, this is not a big deal. You just refrain from using Port Set 0 and go eat some cookies. Or, you can set up the NAPT owning Port Set 0 to only use ports 1024-2048 (instead of 0-2048). (You'd assign that particular port set to low-traffic CEs.) But I guess the IETF wasn't having any of that, and decided to optimize the problem away. It's optional, but also some definition of "recommended." You'll get one extra full port set at the expense of some complexity. You do you.

To understand the solution to the problem, you need to internalize how MAP-T divides the port space. Let's take a look at this table again, and add some binary representations:

| PSID                                | First Port                                         | Last Port                                          |
|-------------------------------------|----------------------------------------------------|----------------------------------------------------|
| 0<sub>10</sub> (00000<sub>2</sub>)  | 0<sub>10</sub> (00000 00000000000<sub>2</sub>)     | 2047<sub>10</sub> (00000 11111111111<sub>2</sub>)  |
| 1<sub>10</sub> (00001<sub>2</sub>)  | 2048<sub>10</sub> (00001 00000000000<sub>2</sub>)  | 4095<sub>10</sub> (00001 11111111111<sub>2</sub>)  |
| 2<sub>10</sub> (00010<sub>2</sub>)  | 4096<sub>10</sub> (00010 00000000000<sub>2</sub>)  | 6143<sub>10</sub> (00010 11111111111<sub>2</sub>)  |
| 3<sub>10</sub> (00011<sub>2</sub>)  | 6144<sub>10</sub> (00011 00000000000<sub>2</sub>)  | 8191<sub>10</sub> (00011 11111111111<sub>2</sub>)  |
| ...                                 | ...                                                | ...                                                |
| 30<sub>10</sub> (11110<sub>2</sub>) | 61440<sub>10</sub> (11110 00000000000<sub>2</sub>) | 63487<sub>10</sub> (11110 11111111111<sub>2</sub>) |
| 31<sub>10</sub> (11111<sub>2</sub>) | 63488<sub>10</sub> (11111 00000000000<sub>2</sub>) | 65535<sub>10</sub> (11111 11111111111<sub>2</sub>) |

See a pattern? Well, the first port always ends in pure zeroes, and the last port always ends in pure ones. But, even more critically, **the first `q` bits of the port number are always its PSID**.

Therefore, we can think of a port number as a 16-bit field which can be subdivided into two separate pieces of information:

![Diagram: Port Number - 2 fields](../images/mapt/port-number-2.svg)

The first field tells you which subdivision ("Set") of the port space the port belongs to, and the second one tells you that port number's index within that group:

![Diagram: Port Division - 2 fields](../images/mapt/port-division-2.svg)

The taboo ports have a similar quirk. 0-1023 happen to be exactly the ports whose first 6 bits are all zero:

![Diagram: Port Number - Taboo](../images/mapt/port-number-taboo.svg)

So that's where we're at. By excluding PSID zero, we effectively also exclude the taboo ports. But we don't want to exclude PSID zero. What do?

The solution is to add a third field to the port number:

![Diagram: Port Number - 3 fields](../images/mapt/port-number-3.svg)

> ![Warning!](../images/warning.svg) Just a heads up: I more or less made up "Port Block" and "Port Index." The RFC sort of uses them, but not in a formal capacity. "Port Block" is actually called `A` (though it's sometimes referred to as `i`), and "Port Index" is called `j`.
> 
> And by the way: Those are the actual values. The *lengths* of these values are `a`, `q` and `m`.

> ![Note!](../images/bulb.svg) In our example, `a = 6`, `q = 5` and `m = 5`. However, they can be whatever non-negative numbers you need them to be, as long as `a + q + m = 16`.

The result is a distribution that looks as follows. Each port number is the result of the binary concatenation of its block, then its set, and then its index:

![Diagram: Port Division - 3 fields](../images/mapt/port-division-3.svg)

What have we accomplished with this? Instead of excluding PSID zero, we now exclude Port Block 0. In other words, instead of excluding half of the ports from the first PSID, we exclude the first <code>2<sup>m</sup></code> ports from every PSID. And now all PSIDs are equal. (Each PSID has <code>(2<sup>a</sup> - 1) * 2<sup>m</sup></code> ports.)

Per the three-subfield diagram above, `a` is the number of bits that will define the Port Block. (It defaults to 6, because that's exactly the number of bits you need to exclude exactly the taboo ports.) `q` is whatever you need your Port Set ID to length (in accordance to your network needs; `q = o - p`). `m` is whatever remains of the port's 16 bits.

> ![Note!](../images/bulb.svg) So what's `k`, you ask? `k` is just a synonym for `q`.

And I know this section has gone for too long already, but there's one more thing to say:

Remember when I said that, despite what the RFC says, the Mapping Rules aren't actually triplets, and you assumed that I said it because the DMR has only one field? There's actually another reason: Mapping Rules are actually 4-tuples. The fourth field is `a`:

	{
		<Rule IPv6 Prefix>,
		<Rule IPv4 Prefix>,
		<EA-bits length>,
		<a>
	}

The RFCs seem to be under the impression that `a`, `k` and `m` need to be instance-wide configuration parameters, but the problem is that it forces all the MAP Domains connected to one particular CE/BR to have the same `a`, `k` and `m` values. This might give you some headaches depending on how awkwardly arranged your available IPv4 addresses are.

I have a proof of concept that demonstrates that there is no technical reason to deal with that. Each MAP Domain should be perfectly able to have its own `a`, `k` and `m`, which is why Jool's implementation includes `a` in both BMRs and FMRs.

> ![Note!](../images/bulb.svg) If you're wondering why Mapping Rules need to define `a` but not `k` nor `m`, note that they already have an implicit `k` (`k = q = o - p`, `o` being the EA-bits length and `p` being the suffix length of the Rule IPv4 Prefix), and `m` is just `16 - a - k`.

### FMR on the CE

> ![Warning!](../images/warning.svg) Under Construction.

The CEs also have an FMR table. When an outgoing destination address matches one of the FMRs, the FMR is used as translation method instead of the DMR. This allows the clients of CEs to communicate directly with the clients of other CEs, without having to use the BR as a middleman.

(Again, each BMR in the FMR table allows communication to a different MAP domain.)

In fact, a CE's BMR is usually added to its own FMR table. This allows clients from a MAP domain's CE to speak directly with other clients from the same MAP domain, but different CE.


