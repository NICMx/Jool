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

As far as we know, Jool is a [compliant](intro-jool.html#compliance) SIIT and Stateful NAT64.

Its latest version is [4.1.0](downloads.html#41x) and its most mature version is [4.0.9](downloads.html#40x).

-------------------

## Survey

<iframe src="https://docs.google.com/forms/d/e/1FAIpQLSe_9_wBttFGd9aJ7lKXiJvIN7wWZm_C6yy3gU0Ttepha275nQ/viewform?embedded=true" width="640" height="300" frameborder="0" marginheight="0" marginwidth="0">Loading…</iframe>

-------------------

## Latest News

### 2020-06-16

[Jool 4.1.0](download.html) has been released.

Improvements:

1. [#136](https://github.com/NICMx/Jool/issues/136): Implement [`lowest-ipv6-mtu`](usr-flags-global.html#lowest-ipv6-mtu).
2. Implement shallow translation of ICMP extensions. (RFC 7915 pp. [13](https://tools.ietf.org/html/rfc7915#page-13), [22](https://tools.ietf.org/html/rfc7915#page-22))
3. [#329](https://github.com/NICMx/Jool/issues/329): Add support for kernel 5.7.

There is one downgrade:

1. 4.1.0 drops support for kernels 3.13 - 3.15, and RHEL 7.0 - 7.5. Here's the updated [compatibility table](intro-jool.html#compatibility).

Also, note that `lowest-ipv6-mtu`'s paranoid default might induce unnecessary fragmentation. If you want 4.1.0 to reach 4.0.9's performance, please review the [MTU documentation](mtu.html).
