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

- The most mature version is [4.1.13](download.html#41x).
- **jool.mx is no longer maintained. Please use https://nicmx.github.io/Jool instead.**

-------------------

## Latest News

### 2024-08-23

Version 4.1.13 has been released. Bugfixes:

- [#410](https://github.com/NICMx/Jool/issues/410):
	1. Move `joold` to [`jool session proxy`](usr-flags-session.html#proxy)
	2. Move `jool joold advertise` to [`jool session advertise`](usr-flags-session.html#advertise)
- [Debian#1074120](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1074120): Fix implementation of kernel modules' `make distclean`
- [#421](https://github.com/NICMx/Jool/issues/421): [`jool session follow`](usr-flags-session.html#follow)
- [#422](https://github.com/NICMx/Jool/pull/422): Patch compilation on 32-bit architectures
- [e8c49da](https://github.com/NICMx/Jool/commit/e8c49daaa5ae2fc5e75ad4bf7079b815775f1a50): Allow pool6 with prefix length ≠ 96 on joold
- [78812d6](https://github.com/NICMx/Jool/commit/78812d66d5b1b7e3ae767b24a1e12bd9dc5b2eab): Deprecate and no-op `--ss-flush-asap`
- [80760bb](https://github.com/NICMx/Jool/commit/80760bbc6e972cad0ea3ecff7d6452077b0222f4): Stop the userspace client from killing itself when the kernel module sends an unknown stat
- [5150753](https://github.com/NICMx/Jool/commit/51507535de7d621263544237485bed3085ae3643): Drop `XTABLES_DISABLED`. (The kernel module now automatically detects whether the kernel was compiled with xtables support. The userspace client still needs to be told with `./configure --with-xtables=no`.)
