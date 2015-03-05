---
layout: documentation
title: Documentation - Userspace Application Flags
---

[Documentation](doc-index.html) > [Userspace Application](doc-index.html#userspace-application) > Flags

# Flags

## Introduction

This compilation of documents explain the flags and options of Jool's userspace applications (`jool_siit` and `jool`).

See the [compilation and installation](usr-install.html) instructions if you still don't have the binaries.

If a command changes the behavior of Jool, it requires network admin privileges (<a href="http://linux.die.net/man/7/capabilities" target="_blank">CAP_NET_ADMIN</a>).

## Index

Common options:

1. [`--help`](usr-flags-help.html)
2. [`--global`](usr-flags-global.html)
	1. [Atomic Fragments](usr-flags-atomic.html)
	2. [MTU Plateaus (Example)](usr-flags-plateaus.html)
3. [`--pool6`](usr-flags-pool6.html)
4. [`--pool4`](usr-flags-pool4.html)

`jool_siit`-only options:

1. [`--eamt`](usr-flags-eamt.html)
2. [`--errorAddresses`](usr-flags-error-addresses.html)

`jool`-only options:

1. [`--bib`](usr-flags-bib.html)
2. [`--session`](usr-flags-session.html)
3. [`--quick`](usr-flags-quick.html)

