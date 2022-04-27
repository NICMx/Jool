---
language: en
layout: default
category: Home
title: Home
---

# Home

-------------------

## Introduction

Jool is an Open Source [SIIT and NAT64](intro-xlat.html) for Linux.

* [Click here](documentation.html) to start getting acquainted with the software.
* [Click here](download.html) to download Jool.

-------------------

## Status

> ![Warning](../images/warning.svg) The project's development has slowed down to essential maintenance. Bugfixing and support will remain active, but there will be no new features in the foreseeable future.

- The most mature version is [4.1.8](download.html#41x).
- The second release candidate for version [4.2.0](download.html#42x) is also available now.

-------------------

## Survey

<iframe src="https://docs.google.com/forms/d/e/1FAIpQLSdeqszHfo-vjQY2uG4mZC3cIy1wQVg5BBs0zUPA5ZuA96Li4w/viewform?embedded=true" width="640" height="560" frameborder="0" marginheight="0" marginwidth="0">Loading…</iframe>

-------------------

## Latest News

### 2022-03-20

Version 4.1.8 has been released.

- [#366](https://github.com/NICMx/Jool/issues/366), [#375](https://github.com/NICMx/Jool/issues/375): Fix checksums in Slow Path.  
  This is a fairly critical bug; please upgrade. It affects packets that fulfill the following conditions:
	- IPv4-to-IPv6
	- Not ICMP error
	- Incoming packet's DF was disabled
	- Packet was large, or GRO-aggregated
- Add validation to more verbosely reject IPv6 packets that contain more than one fragment header.
- Add validation to more verbosely reject fragmented (and not reassembled by `nf_defrag_ipv*`) ICMP errors.  
  (Aside from being fairly illegal, these packets cannot be translated because the "ICMPv6 length" of the [ICMP pseudoheader](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6#Checksum) is unknown.)
- Bugfix: When routing TCP/UDP fragments, the code was including header ports even though nonzero fragment-offset packets lack TCP/UDP headers.  
  This bug probably doesn't affect you, unless your routing is somehow port-based.

Also, please consider answering the [survey above](#survey).

