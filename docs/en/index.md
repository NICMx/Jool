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

- The most mature version is [4.1.12](download.html#41x).
- The second release candidate for version [4.2.0](download.html#42x) is also available now.
- **jool.mx is no longer maintained. Please use https://nicmx.github.io/Jool instead.**

-------------------

## Latest News

### 2024-06-22

Version 4.1.12 has been released. Bugfixes:

- [#410](https://github.com/NICMx/Jool/issues/410): Fix several joold bugs. Also, add [joold stats](config-joold.html#stats-server-port).
- Add [support](intro-jool.html#compatibility) for kernels 6.8, 6.9, 6.10(-rc4), RHEL 8.10 and 9.4. (No changes needed.)
- Patch some rust in the ["graybox" testing framework](https://github.com/NICMx/Jool/tree/main/test/graybox).
