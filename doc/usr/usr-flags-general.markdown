---
layout: documentation
title: Documentation - Userspace Application
---

# Userspace Application > Flags > \--general

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Examples](#examples)
4. [Keys](#keys)
   1. [\--dropAddr](#dropaddr)
   2. [\--dropInfo](#dropinfo)
   3. [\--dropTCP](#droptcp)
   4. [\--toUDP](#toudp)
   5. [\--toTCPest](#totcpest)
   6. [\--toTCPtrans](#totcptrans)
   7. [\--toICMP](#toicmp)
   8. [\--maxStoredPkts](#maxstoredpkts)
   9. [\--setTC](#settc)
   10. [\--setTOS](#settos)
   11. [\--TOS](#tos)
   12. [\--setDF](#setdf)
   13. [\--genID](#genid)
   14. [\--boostMTU](#boostmtu)
   15. [\--plateaus](#plateaus)
   16. [\--minMTU6](#minmtu6)

[Back to Flags](usr-flags.html).

## \--general

## Description

Controls several of Jool's internal variables.

* Issue an empty `--general` command to display the current values of all of Jool's options.
* Enter a key and a value to edit the key's variable.

`--general` is the default configuration mode, so you never actually need to input that one flag.

## Syntax

	jool [--general]
	jool [--general] <flag key> <new value>

## Examples

{% highlight bash %}
$ # Display the configuration values, keys and values.
$ jool --general
$ # Same thing, shorter version.
$ # BTW: This looks very simple, but it still requires Jool's kernel module to be active.
$ jool
$ # Turn "address dependent filtering" on.
$ # true, false, 1, 0, yes, no, on and off all count as valid booleans.
$ jool --general --dropAddr true
{% endhighlight %}

## Keys

The following flag keys are available:

### \--dropAddr

- Name: Address-dependent filtering
- Type: Boolean
- Default: OFF

Suppose _n6_ is talking with _n4a_ via the NAT64:

![Fig.1: Legal chat](images/usr-dropaddr-1.svg)

The relevant [BIB entry](misc-bib.html) is

| IPv6 transport address | IPv4 transport address | Protocol |
|------------------------|------------------------|----------|
| 2001:db8::1#10         | 192.0.2.1#10           | TCP      |

_n4b_ realizes the existence of _n6_'s service, perhaps because _n4a_ tells him about it:

![Fig.2: n4b finds about n6](images/usr-dropaddr-2.svg)

Then _n4b_ tries to chat _n6_ too:

![Fig.3: suspicious query](images/usr-dropaddr-3.svg)

Because the BIB entry exists, _J_ knows that _n4b_ means "2001:db8::1#10" when he says "192.0.2.1#10", so the packet can technically be translated. However, because of the session tables, _J_ can also tell that _n6_ hasn't been talking to _n4b_ in the past.

If `--dropAddr` is OFF, _J_ will allow _n4b_'s packet to pass. If `--dropAddr` is ON, _J_ will drop _n4b_'s packet and respond with a "Communication Administratively Prohibited" ICMP error. This effectively wrecks any IPv4-started communication attempts, even if there are BIB entries (static or otherwise).

* If you're using the NAT64 to publish a IPv6-only service to the IPv4 Internet, it makes sense for `--dropAddr` to be OFF. This is because clients are expected to find out about the IPv6 service on their own, and the server doesn't normally start packet streams.
* If you're using the NAT64 to allow IPv6 nodes to browse the IPv4 Internet, it makes sense for `--dropAddr` to be ON. This is because clients choose their ports at random; it is suspicious for random outsider nodes to guess these ports.

### \--dropInfo

- Name: Filtering of ICMPv6 info messages
- Type: Boolean
- Default: OFF

If you turn this on, pings (both requests and responses) will be blocked while being translated from ICMPv6 to ICMPv4.

For some reason, we're not supposed to block pings from ICMPv4 to ICMPv6, but since you need both a request and a response for a successful echo, the outcome seems to be the same.

This rule will not affect Error ICMP messages.

### \--dropTCP

- Name: Dropping externally initiated TCP connections
- Type: Boolean
- Default: OFF

Turn `--dropTCP` ON to wreck any attempts of IPv4 nodes to initiate TCP communication to IPv6 nodes.

Of course, this will not block IPv4 traffic if some IPv6 node first requested it.

### \--toUDP

- Name: UDP session lifetime
- Type: Intege
