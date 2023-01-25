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

- The most mature version is [4.1.9](download.html#41x).
- The second release candidate for version [4.2.0](download.html#42x) is also available now.
- **jool.mx is no longer maintained. Please use https://nicmx.github.io/Jool instead.**

-------------------

## Latest News

### 2023-01-25

Version 4.1.9 has been released. Bugfixes:

- [#347](https://github.com/NICMx/Jool/issues/347): Allow new Jool binaries to interact with other binaries sharing the same major and minor number versions.
- [#378](https://github.com/NICMx/Jool/issues/378): Fix randomly incomplete `stats display` table print.
- [#379](https://github.com/NICMx/Jool/issues/379), [#380](https://github.com/NICMx/Jool/issues/380), [#395](https://github.com/NICMx/Jool/issues/395): Add support for kernels 5.17, 5.18, 5.19, 6.0, 6.1, RHEL8.6, RHEL8.7, RHEL9.0 and RHEL9.1. Drop support for RHEL8.5.
- [#388](https://github.com/NICMx/Jool/issues/388), [#389](https://github.com/NICMx/Jool/issues/389): Fix sample atomic configuration in the documentation.
- [#391](https://github.com/NICMx/Jool/issues/391), [#392](https://github.com/NICMx/Jool/issues/392): Update OpenWRT installation documentation.
- [#396](https://github.com/NICMx/Jool/issues/396): Allow (and fix during translation, adding mandated padding) ICMP errors containing both ICMP extensions and internal packets measuring less than 128 bytes.
