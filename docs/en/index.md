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

Its latest version is [4.1.4](download.html#41x) and its most mature version is [4.0.9](download.html#40x).

-------------------

## Survey

<iframe src="https://docs.google.com/forms/d/e/1FAIpQLSe_9_wBttFGd9aJ7lKXiJvIN7wWZm_C6yy3gU0Ttepha275nQ/viewform?embedded=true" width="640" height="300" frameborder="0" marginheight="0" marginwidth="0">Loading…</iframe>

-------------------

## Latest News

### 2020-10-07

[Jool 4.1.4](download.html) has been released.

Bugfixes:

1. [#341](https://github.com/NICMx/Jool/issues/341): Deprecate "blacklist4," add replacement "denylist4."
2. [#342](https://github.com/NICMx/Jool/issues/342): Add /32 to the generic denylist again. (And remove secondary addresses, since nobody has actually requested them.)
3. [#343](https://github.com/NICMx/Jool/issues/343): Clarify some documentation. (WIP)

I also largely rewrote the [intro to xlat](https://nicmx.github.io/Jool/en/intro-xlat.html), to reflect the changes from the MAP-T branch. Feedback would be appreciated.

> Remember that `lowest-ipv6-mtu`'s paranoid default might induce unnecessary fragmentation. If you want Jool 4.1 to reach 4.0's performance, please review the [MTU documentation](mtu.html).

