---
layout: index
title: Jool - Home
---

# Home

-------------------

## Introduction

Jool is a [stateful NAT64](intro.html) for Linux.

* [Click here](tutorial1.html) to start getting acquainted with the software.
* [Click here](download.html) to download Jool.

-------------------

## Status

If you want to know what the development team is currently tweaking, you should always be able to answer that by having a look at the latest milestone - <a href="https://github.com/NICMx/NAT64/issues/milestones" target="_blank">milestone list</a>.

But just to make things clear, this is the status of the project as of now:

Jool is still a couple of features away from being 100% RFC 6146 compliant:

1. <a href="https://github.com/NICMx/NAT64/issues/41" target="_blank">Filtering policies</a>
2. <a href="https://github.com/NICMx/NAT64/issues/58" target="_blank">Simultaneous open of TCP connections</a>

That doesn't stop the IPv6-IPv4 translation mechanism from being functional, however.

There are other <a href="https://github.com/NICMx/NAT64/issues?state=open" target="_blank">known issues</a>. Because we have perceived users to be more interested in these latter problems, we intend to postpone the missing features.

Now cooking version 3.1.4...

-------------------

## News

### 2014-03-26

Version 3.1.3 released. Fixes:

1. An <a href="https://github.com/NICMx/NAT64/issues/81" target="_blank">incorrect implementation</a> used to ban configuration on certain systems.
2. A <a href="https://github.com/NICMx/NAT64/issues/79" target="_blank">bug</a> used to prevent Jool from sending certain ICMP errors.
3. A <a href="https://github.com/NICMx/NAT64/issues/83" target="_blank">memory leak</a>.
4. Slightly optimized the packet translation algorithm by <a href="https://github.com/NICMx/NAT64/issues/69" target="_blank">replacing some spinlocks with RCUs</a>.

### 2014-03-04

Website released. *This website!*

And with it comes a new release. 3.1.2 fixes:

1. <a href="https://github.com/NICMx/NAT64/issues/76" target="_blank">21-centuried the userspace-app's installation procedure</a>.
2. <a href="https://github.com/NICMx/NAT64/issues/77" target="_blank">Jool is now more explicit regarding the suffix of prefixes</a>.
3. <a href="https://github.com/NICMx/NAT64/issues/78" target="_blank">Jool no longer wrecks itself when modprobed with invalid arguments</a>.

### 2014-02-21

Version 3.1.1 released.

It contains two bugfixes:

1. <a href="https://github.com/NICMx/NAT64/issues/75" target="_blank">Added permission checking to the admin-related userspace requests.</a>
2. <a href="https://github.com/NICMx/NAT64/issues/72" target="_blank">Fixed compatibility issues with ~3.1 kernels.</a>

### 2014-01-15

Version 3.1.0 released. Jool finally handles fragments!

Other important fixes:

* Major optimizations on both the BIB and session databases. The module should scale a lot more gracefully as clients demand more traffic.
* Jool no longer requires a separate IPv4 address.
* Kernel panic during removal of the module fixed.
* And <a href="https://github.com/NICMx/NAT64/issues?milestone=11&state=closed" target="_blank">More stuff</a>.

