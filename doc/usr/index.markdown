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

Our next target is **Simultaneous open of TCP connections**. Now cooking version 3.2.0...

-------------------

## News

### 2014-06-18

Version 3.1.5 released.

Our most important fix is <a href="https://github.com/NICMx/NAT64/issues/92" target="__blank">issue #92</a>. Incorrect ICMP errors used to confuse IPv4 nodes, which lowered the reliability of 4-to-6 traffic.

Aside from that, the userspace application has been tightened. It doesn't crash silly anymore when it has to <a href="https://github.com/NICMx/NAT64/issues/88" target="__blank">output large BIB or session tables</a>, and <a href="https://github.com/NICMx/NAT64/issues/65" target="__blank">works a lot harder to keep the database free from trashy leftover records</a>.

Then we have a couple of <a href="https://github.com/NICMx/NAT64/issues/60" target="__blank">performance</a> <a href="https://github.com/NICMx/NAT64/issues/60" target="__blank">optimizations</a>. In particular (and more or less as a side effect), by aligning log priorities to those from the rest of the kernel, more care has been taken to keep the log cleaner.

If you care about performance, you might want to read the <a href="https://github.com/NICMx/NAT64/issues/91" target="__blank">as-of-now</a>-missing [documentation of `--minMTU6`](userspace-app.html#minmtu6), a configuration parameter that helps you avoid fragmentation.

If people doesn't find critical bugs in this version, this appears to be the end of the 3.1.x series. We'll go back to aim for 100% RFC compliance in the next update.

### 2014-04-25

Version 3.1.4 released. Fixes:

1. Two <a href="https://github.com/NICMx/NAT64/issues/90" target="_blank">kernel</a> <a href="https://github.com/NICMx/NAT64/issues/84" target="_blank">crashes</a>.
2. The userspace application now <a href="https://github.com/NICMx/NAT64/issues/86" target="_blank">resolves names</a>.
3. <a href="https://github.com/NICMx/NAT64/issues/87" target="_blank">Added support</a> for Linux 3.13+.

Also, we <a href="https://github.com/NICMx/NAT64/issues/90" target="_blank">no longer recommend usage of Jool in kernel 3.12</a>.

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

