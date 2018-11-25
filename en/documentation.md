---
language: en
layout: default
category: Documentation
title: Documentation Index
---

# Documentation

Welcome to Jool's documentation index.

## Introduction

1. [What is SIIT/NAT64?](intro-xlat.html)
2. [What is Jool?](intro-jool.html)

See [RFC 6586](https://tools.ietf.org/html/rfc6586) for deployment experiences using Stateful NAT64.

## Installation

1. [Installation on OpenWRT](openwrt.html)
2. [Installation on most other distros](install.html)

## Basic Tutorials

1. [SIIT](run-vanilla.html)
2. [SIIT + EAM](run-eam.html)
3. [Stateful NAT64](run-nat64.html)
4. [DNS64](dns64.html)

## IP/ICMP Translation in Detail

1. [The IPv6 Address Pool](pool6.html)

## SIIT in Detail

1. [The EAMT](eamt.html)
2. [Untranslatable IPv6 addresses](pool6791.html)

## NAT64 in Detail

1. [The IPv4 Transport Address Pool](pool4.html)
2. [BIB](bib.html)

## Userspace Clients

1. [General usage](usr-clients.html)
1. Common modes
	4. [`instance`](usr-flags-instance.html)
	2. [`stats`](usr-flags-stats.html)
	2. [`global`](usr-flags-global.html)
		1. [`mtu-plateaus`](usr-flags-plateaus.html)
2. `jool_siit`-only modes
	1. [`eamt`](usr-flags-eamt.html)
	2. [`blacklist4`](usr-flags-blacklist4.html)
3. `jool`-only modes
	1. [`pool4`](usr-flags-pool4.html)
	2. [`bib`](usr-flags-bib.html)
	3. [`session`](usr-flags-session.html)
	4. [`joold`](usr-flags-joold.html)

## Other Configuration

1. [Atomic Configuration](config-atomic.html)
2. [`joold`](config-joold.html)

## Defined Architectures

1. [SIIT-DC](siit-dc.html)
2. [464XLAT](464xlat.html)
3. [SIIT-DC: Dual Translation Mode](siit-dc-2xlat.html)

## Other Sample Runs

1. [Single Interface](single-interface.html)
2. [Node-Based Translation](node-based-translation.html)
3. [Session Synchronization](session-synchronization.html)

## Miscellaneous

1. [FAQ](faq.html)
2. [Logging](logging.html)
3. [MTU and Fragmentation](mtu.html)
4. [Offloads](offloads.html)

