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

Its most mature version is [4.0.9]({{ site.repository-url }}/milestone/48).

-------------------

## Survey

<iframe src="https://docs.google.com/forms/d/e/1FAIpQLSe_9_wBttFGd9aJ7lKXiJvIN7wWZm_C6yy3gU0Ttepha275nQ/viewform?embedded=true" width="640" height="300" frameborder="0" marginheight="0" marginwidth="0">Loading…</iframe>

-------------------

## Latest News

### 2020-05-05

[Jool 4.0.9](download.html) has been released.

Bugfixes:

1. [#325](https://github.com/NICMx/Jool/issues/325): Patch userspace compilation error triggered when different versions of Jool's libraries are already installed in the system.
2. [#326](https://github.com/NICMx/Jool/issues/326): Patch userspace-kernel communication on newer kernels. (This bug was introduced in Jool 4.0.8.)
3. Added support for kernel 5.6.

In other news, Jool 4.0.7 is now available in Ubuntu 20.04 (Focal Fossa)'s stable release:

	sudo apt install jool-dkms jool-tools
