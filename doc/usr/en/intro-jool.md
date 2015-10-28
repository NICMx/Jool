---
language: en
layout: default
category: Documentation
title: Introduction to Jool
---

[Documentation](documentation.html) > [Introduction](documentation.html#introduction) > What is Jool?

# Introduction to Jool

## Index

1. [Overview](#overview)
2. [Compliance](#compliance)
3. [Compatibility](#compatibility)

## Overview

Jool is an Open Source implementation of [IPv4/IPv6 Translation](intro-nat64.html) on Linux. Until version 3.2.x, it used to be only a Stateful NAT64; starting from 3.3.0, it also supports SIIT mode.

## Compliance

As far as we know, this is the compliance status of Jool 3.3:

| RFC/draft | Reminder name | Status |
|-----------|---------|--------|
| [RFC 6052](https://tools.ietf.org/html/rfc6052) | IP address translation | Fully compliant. |
| [RFC 6144](https://tools.ietf.org/html/rfc6144) | IPv4/IPv6 Translation Framework | Fully compliant. |
| [RFC 6145](https://tools.ietf.org/html/rfc6145) | SIIT | The atomic fragment implementation is generally broken (see _Atomic Fragment Deprecation_ below). Otherwise compliant. |
| [RFC 6146](https://tools.ietf.org/html/rfc6146) | Stateful NAT64 | Mostly compliant.<br />(Inherits RFC 6145 compliance issues) |
| [RFC 6384](http://tools.ietf.org/html/rfc6384) | FTP over NAT64 | [Not yet compliant](https://github.com/NICMx/NAT64/issues/114). |
| [RFC 6791](https://tools.ietf.org/html/rfc6791) | ICMP quirks | In short, this RFC wants two things: A pool of IPv4 addresses and an ICMP header extension. Jool implements the former but not the latter. |
| [RFC 6877](http://tools.ietf.org/html/rfc6877) | 464XLAT | Rather implemented as SIIT-DC-DTM; see below. |
| [draft-ietf-v6ops-siit-dc]({{ site.draft-siit-dc }}) | SIIT-DC | Fully compliant. |
| [draft-ietf-v6ops-siit-dc-2xlat]({{ site.draft-siit-dc-2xlat }}) | SIIT-DC: Dual Translation Mode | Fully compliant. |
| [draft-ietf-6man-deprecate-atomfrag-generation]({{ site.draft-deprecate-atomfrag-generation }}) | Atomic Fragment Deprecation | Strictly speaking, the draft wants us to completely trash the atomic fragments concept. We do implement them -poorly- as an [alternate and utterly discouraged mode](usr-flags-atomic.html#overview). |
| [draft-anderson-v6ops-siit-eam]({{ site.draft-siit-eam }}) | EAM | Fully compliant. |

Please [let us know](https://github.com/NICMx/NAT64/issues) if you find additional compliance issues or RFCs/drafts we've missed.

## Compatibility

We're supposed to support Linux kernels 3.0.0 and up. While most of the development time has been spent experimenting on Ubuntu 12.04 and 14.04 using current kernels, we've performed a healthy amount of formal testing on Jool 3.1.5 and 3.2.2 in the following variants:

| Distribution | Kernels |
| -------------|---------|
| CentOS 7 | 3.10.0-123.el7.x86_64 |
| Debian 7.5 | 3.2.0-4-amd64 |
| Red Hat Enterprise Linux 7 | 3.10.0-123.4.4.el7.x86_64 |
| SuSE Linux Enterprise Desktop 11 SP3 | 3.0.101-0.31-default |
| Ubuntu 12.04 | 3.1.10-030110-generic, 3.2.60-030260-generic |
| Ubuntu 12.10 | 3.3.8-030308-generic, 3.4.94-030494-generic, 3.5.7-03050733-generic |
| Ubuntu 13.04 | 3.6.11-030611-generic, 3.7.10-030710-generic, 3.8.13-03081323-generic |
| Ubuntu 13.10 | 3.9.11-030911-generic, 3.10.44-031044-generic, 3.11.10-03111011-generic |
| Ubuntu 14.04 | 3.12.22-031222-generic, 3.13.11-03131103-generic |
| Ubuntu 14.10 | 3.14.8-031408-generic, 3.15.1-031501-generic |

Red Hat and CentOS introduce a compilation warning due to a kernel version mismatch between Red Hat-based kernels and Debian-based kernels. <a href="https://github.com/NICMx/NAT64/issues/105" target="_blank">We're still researching ways to address this warning</a>, but it hasn't caused any problems during testing.

