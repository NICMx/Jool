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

- The most mature version is [4.1.10](download.html#41x).
- The second release candidate for version [4.2.0](download.html#42x) is also available now.
- **jool.mx is no longer maintained. Please use https://nicmx.github.io/Jool instead.**

-------------------

## Latest News

### 2023-06-11

Version 4.1.10 has been released. Bugfixes:

- [#382](https://github.com/NICMx/Jool/issues/382), [#400](https://github.com/NICMx/Jool/issues/400): Clean up `skb->tstamp` during translation to prevent dropped packets.
- [#401](https://github.com/NICMx/Jool/issues/401), [#404](https://github.com/NICMx/Jool/issues/404): Improve validations for userspace requests.
- [#405](https://github.com/NICMx/Jool/issues/405): Add support for kernels 6.2 and 6.3.
- [#406](https://github.com/NICMx/Jool/issues/406), [Debian#1029268](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1029268): Modernize references to libxtables shared object functions.
