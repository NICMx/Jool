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

As far as we know, Jool is a [generally compliant](intro-jool.html#compliance) SIIT and Stateful NAT64.

Its most mature version is [4.0.8]({{ site.repository-url }}/milestone/47).

-------------------

## Survey

<iframe src="https://docs.google.com/forms/d/e/1FAIpQLSe_9_wBttFGd9aJ7lKXiJvIN7wWZm_C6yy3gU0Ttepha275nQ/viewform?embedded=true" width="640" height="300" frameborder="0" marginheight="0" marginwidth="0">Loading…</iframe>

-------------------

## Latest News

### 2020-03-30

[Jool 4.0.8](download.html) has been released.

Changes:

1. [#320](https://github.com/NICMx/Jool/issues/320): Fixed a memory leak during `modprobe -r`.
2. [#322](https://github.com/NICMx/Jool/issues/322): Modernized the Netlink code to prevent alignment issues during userspace client requests.
