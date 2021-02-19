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

- The most mature version is [4.1.5](download.html#41x).
- [4.0.9](download.html#40x) is soon going to be deprecated.
- The second release candidate for version [4.2.0](download.html#42x) is also available now.

Due to a temporary resource shortage, the project's development has slowed down to essential maintenance. No new features are expected to be developed during the first half of 2021 (at least), but bugfixing and support will remain active.

-------------------

## Survey

<iframe src="https://docs.google.com/forms/d/e/1FAIpQLSe_9_wBttFGd9aJ7lKXiJvIN7wWZm_C6yy3gU0Ttepha275nQ/viewform?embedded=true" width="640" height="300" frameborder="0" marginheight="0" marginwidth="0">Loading…</iframe>

-------------------

## Latest News

### 2021-02-19

Version 4.1.5 has been released. Changelog:

- [#340](https://github.com/NICMx/Jool/issues/340): Patch several joold bugs.
- [#345](https://github.com/NICMx/Jool/issues/345), [#354](https://github.com/NICMx/Jool/issues/354): Improve some documentation. (Includes a [Cheat Sheet](cheat-sheet.html).)
- [#350](https://github.com/NICMx/Jool/issues/350): Remove `CAP_NET_ADMIN` requirement from `stats display`.

The second release candidate for version 4.2.0 is also available. Changelog:

- Patch some [MAP-T address translation bugs](https://github.com/NICMx/Jool/commit/5f19e8a7efcbb4e9df708405c0b4e77d1bbbaec3).
- [Clean](https://github.com/NICMx/Jool/commit/5a46e74e5e1dd03fb62aaa13fac38c5ac1446de7) [up](https://github.com/NICMx/Jool/commit/b7e8ea876a6d155f4d59fe0b0645efadadbf2f08) [unit](https://github.com/NICMx/Jool/commit/6c06470e9bb04c2ce3ea92053d847d674838064d) [tests](https://github.com/NICMx/Jool/commit/76929f81ed720635066223c2b99d165c7cd01d1a).
- [Internal API cleanups](https://github.com/NICMx/Jool/commit/41e3ca69459ae2ab461fdf2c106d1e9bf47d51ff).

As a reminder, here's the MAP-T documentation:

- [Early introduction to MAP-T](intro-xlat.html#map-t)
- [Detailed explanation of MAP-T](map-t.html)
- [Jool MAP-T tutorial](run-mapt.html)
- The code:
	- [tar.gz](https://github.com/NICMx/Jool/releases/download/v4.2.0-rc2/jool-4.2.0.rc2.tar.gz)
	- Debian packages: [kernel](https://github.com/NICMx/Jool/releases/download/v4.2.0-rc2/jool-dkms_4.2.0.rc2-1_all.deb), [userspace](https://github.com/NICMx/Jool/releases/download/v4.2.0-rc2/jool-tools_4.2.0.rc2-1_amd64.deb)

