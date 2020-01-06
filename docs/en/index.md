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

Its most mature version is [4.0.7]({{ site.repository-url }}/milestone/46).

-------------------

## Survey

<iframe src="https://docs.google.com/forms/d/e/1FAIpQLSe_9_wBttFGd9aJ7lKXiJvIN7wWZm_C6yy3gU0Ttepha275nQ/viewform?embedded=true" width="640" height="867" frameborder="0" marginheight="0" marginwidth="0">Loading…</iframe>

-------------------

## Latest News

### 2019-12-17

[Jool 4.0.7](download.html) has been released.

Bugfixes:

1. [#221](https://github.com/NICMx/Jool/issues/221): RFC 7915 review. [Compliance status](file:///home/ydahhrk/git/jool/docs/_site/en/intro-jool.html#compliance) has been updated.
2. [#310](https://github.com/NICMx/Jool/issues/310): Patched communication between 64-bit kernels and 32-bit userspace.
3. [#311](https://github.com/NICMx/Jool/issues/311): Fixed `iptables-save`.
4. [(Lacks issue)](https://www.mail-archive.com/debian-bugs-dist@lists.debian.org/msg1715936.html): Updated DKMS installation to make up for Kbuild's removal of `SUBDIRS` (which seems to have happened in kernel 5.4).

Also, the Debian package was upgraded to [testing](https://wiki.debian.org/DebianTesting), and there are [Alpine](alpine-linux.html) and [Ubuntu](https://launchpad.net/ubuntu/+source/jool) releases now.

Please remember to cast your votes on the survey if you'd like to voice your opinion.
