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

As far as we know, Jool is a [compliant](intro-jool.html#compliance) SIIT and Stateful NAT64. This is the roadmap as of 2017-11-23:

2. [Milestone 4.0.0]({{ site.repository-url }}/issues?q=milestone%3A4.0.0) will be an [internal refactor]({{ site.repository-url }}/issues/140) which should enhance Jool's config versatility.
3. [Milestone 4.1.0]({{ site.repository-url }}/issues?q=milestone%3A4.1.0) will add several more features.

New bug reports might interpolate other milestones in-between. Feedback from users can persuade us to change priorities. See [Contact](contact.html) for options on this.

Our latest release is version [3.5.7]({{ site.repository-url }}/milestone/42).

-------------------

## News

## 2018-05-04

Version 3.5.7 has been released!

The updates are

- [#247](https://github.com/NICMx/Jool/issues/247): Fix unlikely kernel panic.
- [#260](https://github.com/NICMx/Jool/issues/260) and [#263](https://github.com/NICMx/Jool/issues/263): Add support for kernels 4.15 and 4.16.

## 2018-01-16

Version 3.5.6 has been released!

The main update is a change of license. Originally released under the GPLv3+, Jool 3.5.6 and onwards will now operate under the General Public License version 2. This change was prompted due to GPLv3's incompatibilities with the Linux kernel's own license.

Because of this issue, though the remaining patches might be of little interest to you, you are strongly encouraged to update to the newer version. There will be no further official development nor support for older versions.

Other changes include:

- [#255](https://github.com/NICMx/Jool/issues/255): Improved parsing of configuration from JSON files.
- [#256](https://github.com/NICMx/Jool/issues/256): Added support for kernels 4.13 and 4.14.
- Fit the `--pool4 --display` table in 80-column terminals for ease of view.

## 2017-11-23

Version 3.5.5 has been released.

Bugfixes:

1. [#249](https://github.com/NICMx/Jool/issues/249): Fix missing entries from `--eamt --display` output.
2. [#253](https://github.com/NICMx/Jool/issues/253): Fix namespace code for usage of Jool in a container.
3. [Fix random broken connections due to mischosen masking ports](https://github.com/NICMx/Jool/commit/3de64b8e694131893c9a59fa506c02265bb31bf0).
4. `--pool4 --add` and `--pool4 --remove` weren't validating that the given prefix didn't contain suffix bits active. They reacted in different ways no this situation, both of which were wrong.

Performance patches:

1. Improve mask selection algorithm's performance. [Please read this](pool4.html). The default value of Max Iterations is not backwards compatible!

Also, just a heads up: If you monitored the logging message

	I ran out of pool4 addresses.

Then you probably want to know that it changed slightly:

	I'm running out of pool4 addresses for mark <mark>.

If the relevant Max Iterations is `infinity`, then the message triggers when pool4 is exhausted (as it used to). If it isn't, it triggers whenever pool4 failed to find a suitable mark. (Though the message rate-limits itself.)

Misc tweaks:

1. The userspace app now displays assumed mode and operation on most errors.

This should help users troubleshoot problems, particularly when these fields are implicit:

	# jool --pool4 --tcp 192.0.2.1/30
	Jool Error: '192.0.2.1/30' seems to have a suffix; please fix.
	(Error code: 22)
	(Note: Assuming configuration mode '--pool4' and operation '--add'.)

### 2017-07-25

Version 3.5.4 has been released. The improvements are

1. Added support for kernels [4.11](https://github.com/NICMx/Jool/issues/244) and [4.12](https://github.com/NICMx/Jool/issues/248).
2. [Fixed compilation](https://github.com/NICMx/Jool/issues/245) on debugging-enabled kernels.
3. [Improved `make clean`](https://github.com/NICMx/Jool/issues/246) slightly.
4. Added error handling for [#247](https://github.com/NICMx/Jool/issues/247). (The core problem hasn't been found yet, but what used to be a kernel crash has been upgraded to a packet drop and debugging messages.)

### 2017-03-09

Version 3.5.3 has been released.

1. Bugfix: [`--logging-bib`](usr-flags-global.html#--logging-bib) and [`--logging-session`](usr-flags-global.html#--logging-session) weren't logging [UDP and ICMP traffic](https://github.com/NICMx/Jool/issues/241).
2. Added support for [Linux 4.9](https://github.com/NICMx/Jool/issues/236) and [4.10](https://github.com/NICMx/Jool/issues/239).
3. Fixed [build errors on some platforms](https://github.com/NICMx/Jool/pull/237).

### 2016-12-06

Version 3.4.6 has been released.

3.4.6 simply mirrors the [#232](https://github.com/NICMx/Jool/issues/232) fix (already in 3.5.2) into the 3.4 series. You don't need to downgrade if you're using Jool 3.5.

### 2016-12-02

Version 3.5.2 has been released.

1. [Fixed a kernel panic](https://github.com/NICMx/Jool/issues/232). (Both SIIT and NAT64.)
2. Improved the build system: [#233](https://github.com/NICMx/Jool/issues/233) and [#234](https://github.com/NICMx/Jool/issues/234)
3. [Fixed the RFC6791 pool](https://github.com/NICMx/Jool/issues/235).

### 2016-10-07

Version 3.5.1 has been released. Both apply to NAT64:

1. [Fixed two memory leaks](https://github.com/NICMx/Jool/issues/229).
2. [Silenced fragmentation warning](https://github.com/NICMx/Jool/issues/231).

### 2016-09-26

Version 3.5.0 has been released! The new features are

- [Atomic Configuration](config-atomic.html)
- [Session Synchronization](session-synchronization.html)
- [Namespace Instances](usr-flags-instance.html)
- [A v6 RFC6791 prefix](usr-flags-global.html#--rfc6791v6-prefix)
- Documented Testing Framework ([unit](https://github.com/NICMx/Jool/tree/master/test/unit) and [graybox](https://github.com/NICMx/Jool/tree/master/test/graybox))

Some functionality was dropped:

- Atomic fragment support was [purged](https://github.com/NICMx/Jool/issues/221)
- [`--pool6`](usr-flags-pool6.html) can no longer be [`--quick`](usr-flags-pool4.html#--quick)-removed.

### 2016-09-19

Jool 3.4.5 was released.

1. Added support for [kernels 4.6 and 4.7](https://github.com/NICMx/Jool/issues/219).
2. Deleted constant warning due to an empty pool6.
3. [Improved](https://github.com/NICMx/Jool/issues/223) the implicit blacklist:
	- Blacklisted directed broadcast.
	- Applied the implicit blacklist to EAMT-based translation.  
	  (Among other things, this prevents an overly-intrusive EAMT from hogging packets intended for the translator.)
4. `jool` and `jool_siit` can now be modprobed in the same namespace [without suffering a Netlink socket collision](https://github.com/NICMx/Jool/issues/224).

### 2016-07-11

Version 3.4.4 released. One bug was found:

1. NAT64 Jool's implementation of [empty pool4](usr-flags-pool4.html#notes) used to [mistake point-to-point interface addresses]({{ site.repository-url }}/issues/217), leading to packet drops.

### 2016-04-21

Version 3.4.3 released.

1. Added support for a wider range of kernels. Support is now from Linux 3.2 to 4.4, and also RHEL 7.0 to 7.2.
2. New configuration flag for NAT64: [`--f-args`](usr-flags-global.html#--f-args)
3. New configuration flag for NAT64: [`--handle-rst-during-fin-rcv`](usr-flags-global.html#--handle-rst-during-fin-rcv)

### 2015-11-20

Version 3.4.2 released. There are three bugfixes:

1. [Bogus pointers and memory leaks]({{ site.repository-url }}/issues/192) caused by `--flush` and termination of pool6791 and blacklist (SIIT Jool).
2. `--bib --display` and `--session --display` now [require network admin privileges]({{ site.repository-url }}/issues/191) (NAT64 Jool).
3. Needlessly purged some [compilation warnings]({{ site.repository-url }}/issues/188) in old gcc versions (NAT64 Jool).

Careful with #2! You might need to update scripts.

### 2015-11-11

Version 3.4.1 released. There are three bugfixes:

1. Kernel panic due to [incorrect namespace API handling]({{ site.repository-url }}/pull/185#issuecomment-155875381).
2. Fixed [compilation for kernels 4.1 and above]({{ site.repository-url }}/pull/185).
3. The userspace applications [used to return success after errors found by the module]({{ site.repository-url }}/issues/184).

### 2015-11-04

Version 3.4.0 released. This is a fat one.

1. Refactors to pool4 add [mark-dependent sourcing](usr-flags-pool4.html#--mark) and [port ranges](usr-flags-pool4.html#examples) (which in turn removes [the need for a second IPv4 address](run-nat64.html#sample-network)), and fixes the [excessive memory usage]({{ site.repository-url }}/issues/36).
2. The EAMT now implements [Hairpinning]({{ site.repository-url }}/issues/162) and [overlapping entries]({{ site.repository-url }}/issues/160), which are newer updates to the EAM draft.
3. Minimal namespace features, which allow Host-Based Edge Translation (now called [Node-Based Translation](node-based-translation.html)) and (subjectively) [better filtering]({{ site.repository-url }}/issues/41).
4. The userspace application now [prints the friendlier error messages]({{ site.repository-url }}/issues/169) that used to be dumped in the kernel log only.
5. Removed reliance on dead code deletion, [which used to prevent compilation on some systems]({{ site.repository-url }}/issues/152).
6. [Two]({{ site.repository-url }}/issues/174) [bugfixes]({{ site.repository-url }}/issues/173).
7. [A spanish version of this site](../es/index.html).
8. `--csv` can now be used on [all configuration targets]({{ site.repository-url }}/issues/164#issuecomment-126093571).

> ![Warning](../images/warning.svg) If you want to upgrade, please keep in mind pool4 is not completely backwards-compatible. In Jool 3.3, any packet would be masked using any available pool4 entry. In Jool 3.4, every pool4 entry only masks packets wielding specific marks (which defaults to zero). See [`--mark`](usr-flags-pool4.html#--mark) for more details.

### 2015-10-15

Version 3.3.5 released.

Three bugfixes:

1. A connection could be masked using port zero (NAT64 Jool).
2. Incorrect routing when pool6791 was empty (SIIT Jool).
3. Memory leak on `--eamt --flush` (SIIT Jool).

### 2015-09-21

Version 3.3.4 released.

The most important fix is (theoretically) a [Path MTU Discovery breaker]({{ site.repository-url }}/issues/170). There's also the [now automatic blacklisting of IPv4 multicast]({{ site.repository-url }}/issues/168) and the [better handling of the IPv6 header's hop limit]({{ site.repository-url }}/issues/167).

Also, it has been noticed [SIIT Jool installations in kernels 3.5 and below need IPv4 forwarding active]({{ site.repository-url }}/issues/170#issuecomment-141507174). In other words, add

	sudo sysctl -w net.ipv4.conf.all.forwarding=1

to the modprobe procedure.

### 2015-08-17

[Critical bug detected!]({{ site.repository-url }}/issues/166)

In addition, version 3.3.3 contains the following:

1. [Added support for the DKMS framework!]({{ site.repository-url }}/pull/165)
2. Userspace application quirks fixed: [#150]({{ site.repository-url }}/issues/150), [#151]({{ site.repository-url }}/issues/151).

### 2015-04-14

Version 3.3.2 released.

This is the summary:

- There are new configuration flags:
	- [`--source-icmpv6-errors-better`](usr-flags-global.html#--source-icmpv6-errors-better)
	- [`--logging-bib`](usr-flags-global.html#--logging-bib) and [`--logging-session`](usr-flags-global.html#--logging-session)
- The userspace app was misbehaving in several ways. While all of its bugs had workarounds, it was a pain to use.

Also, unrelated to the code, we now have two mailing lists:

- jool-news@nic.mx is intended to spread news. Since we currently don't have other major events, the plan is to only use it to announce new releases coming out. [Click here](https://mail-lists.nic.mx/listas/listinfo/jool-news) to start listening.
- jool-list@nic.mx can be used for public discussion (help, proposals, whatever). I will also drop the news here so people doesn't have to subscribe to both at a time. [Click here](https://mail-lists.nic.mx/listas/listinfo/jool-list) to register.

[jool@nic.mx](mailto:jool@nic.mx) can still be used to reach us developers only.

We'd also like to apologize for the [certificate hiccup we had recently]({{ site.repository-url }}/issues/149). Though they are being generated, the mailing list archives are also not available yet, and this is in our admins' TODO list.

### 2015-03-11

[Important bug]({{ site.repository-url }}/issues/137) discovered!

We just released Jool 3.3.1.

### 2015-03-09

Jool 3.3.0 is finished.

[Filtering couldn't make it into the milestone]({{ site.repository-url }}/issues/41#issuecomment-76861510), but Stateless IP/ICMP Translation (SIIT) is now supported.

See the updated [SIIT/NAT64 introduction](intro-xlat.html) for an improved picture of the SIIT paradigm. [Here's the tutorial](run-vanilla.html). Also keep an eye on [464XLAT](464xlat.html).

We also refactored the userspace app somewhat; please review your scripts:

- The kernel's per-interface MTU setting [replaced `--minMTU6`](mtu.html).
- `--address`, `--prefix`, `--bib4` and `--bib6` were deprecated because they're considered redundant. See [`--pool6`](usr-flags-pool6.html), [`--pool4`](usr-flags-pool4.html) and [`--bib`](usr-flags-bib.html).
- Three global flags were also deprecated for [different reasons](usr-flags-atomic.html).

We also released Jool 3.2.3, which is [bugfixes]({{ site.repository-url }}/milestones/3.2.3) since 3.2.2. One of the bugs is a DoS vulnerability, so upgrading to at least 3.2.3 is highly recommended.

### 2014-10-24

An <a href="{{ site.repository-url }}/issues/112" target="_blank">important bug</a> was discovered, and version 3.2.2 is out.

### 2014-10-17

The documentation of `--plateaus` proved to be lacking, so there's now a [full article](usr-flags-plateaus.html) dedicated to it. The [original definition](usr-flags-global.html#--mtu-plateaus) also received improvements.

It has come to our attention that <a href="{{ site.repository-url }}/issues/111" target="_blank">we are also lacking an explanation of IP literals</a>, so there should be another codeless update like this in the near future.

### 2014-10-08

Version 3.2.1 released. The 3.2 series is now considered more mature than 3.1.

The important changes are

1. <a href="{{ site.repository-url }}/issues/106" target="_blank">Jool used to always attempt to mask packets using the first prefix of the pool</a>. This meant that Jool was unable to handle more than one prefix.
2. The <a href="{{ site.repository-url }}/issues/109" target="_blank">memory leak in the core</a> has been purged.

The less noticeable ones are

1. `log_martians` <a href="{{ site.repository-url }}/issues/107" target="_blank">is no longer a step</a> in modprobing Jool (though it doesn't bite if you keep it).
2. <a href="{{ site.repository-url }}/issues/57" target="_blank">The SNMP stat updates returned</a>. See `nstat` and `netstat -s`.
3. Corner-case packets now get <a href="{{ site.repository-url }}/issues/108" target="_blank">checksums updated correctly</a>.

### 2014-09-01

It took it a really long time to overcome testing, but version 3.2.0 is finally released.

We changed the minor version number this time, because the userspace application has a slightly different interface; the single-value configuration parameters have been joined: [`--general`](usr-flags-global.html) replaced `--filtering`, `--translate` and `--fragmentation`. The application also has three new features:

1. The <a href="{{ site.repository-url }}/pull/97" target="_blank">ability to flush the pools</a>.
2. The addition of [`--quick`](usr-flags-pool4.html#--quick).
3. The addition of `--svg`, in [BIB](usr-flags-bib.html#csv) and [session](usr-flags-session.html#csv).

The second main novelty is the finally correct implementation of <a href="{{ site.repository-url }}/issues/58" target="_blank">Simultaneous Open of TCP Connections</a>. The translation pipeline should now be completely quirkless.

A <a href="{{ site.repository-url }}/issues/103" target="_blank">little confusion</a> also revealed that the path to libnl <a href="{{ site.repository-url }}/commit/6455ffd898bae996ce3cab37b2fb6a3459ae096b" target="_blank">used to be hardcoded in the configuration script</a>. If you used to have trouble compiling the userspace application, you might want to try again using the new version.

The more unnoticeable stuff includes a <a href="{{ site.repository-url }}/issues/100" target="_blank">complement to the old issue #65</a> and a <a href="{{ site.repository-url }}/issues/56" target="_blank">healthier code-to-comment ratio</a> :). The user documentation, on the other hand, received a significant refactor, so looking at the <a href="{{ site.repository-url }}/commit/752ed2584534e6bf6bd481d7f4d4ababb6424efe" target="_blank">diff</a> might not be overly productive this time.

One thing we did not complete was the <a href="{{ site.repository-url }}/issues/104" target="_blank">fragmentation refactor</a>. This is in fact the reason why this milestone dragged. We appear to really need to reconcile the kernel's defragmenter and the RFC in order to implement filtering policies however, so it's still considered an active issue.

We also released 3.1.6, which is small fixes from 3.1.5, in case somebody has a reason to continue using the 3.1.x series.

### 2014-06-26

By the way:

If you can read <a href="https://help.github.com/articles/github-flavored-markdown" target="_blank">Markdown</a> and Github's diffs, you can find the documentation changes for version 3.1.5 <a href="{{ site.repository-url }}/commit/5295b05cf2c380055c3356d48ef56b74c0b828bb" target="_blank">here</a>, <a href="{{ site.repository-url }}/commit/2732f520b6616955fb81db778eab9da0f1db210c" target="_blank">here</a> and <a href="{{ site.repository-url }}/commit/54fc02dd5f5a22c44ac2d6be092306c34abd30ee" target="_blank">here</a>.

### 2014-06-18

Version 3.1.5 released.

Our most important fix is <a href="{{ site.repository-url }}/issues/92" target="_blank">issue #92</a>. Incorrect ICMP errors used to confuse IPv4 nodes, which lowered the reliability of 4-to-6 traffic.

Aside from that, the userspace application has been tightened. It doesn't crash silly anymore when it has to <a href="{{ site.repository-url }}/issues/88" target="_blank">output large BIB or session tables</a>, and <a href="{{ site.repository-url }}/issues/65" target="__blank">works a lot harder to keep the database free from trashy leftover records</a>.

Then we have a couple of <a href="{{ site.repository-url }}/issues/60" target="_blank">performance</a> <a href="{{ site.repository-url }}/issues/60" target="_blank">optimizations</a>. In particular (and more or less as a side effect), by aligning log priorities to those from the rest of the kernel, more care has been taken to keep the log cleaner.

If you care about performance, you might want to read the <a href="{{ site.repository-url }}/issues/91" target="_blank">as-of-now</a>-missing [documentation of `--minMTU6`](mtu.html), a configuration parameter that helps you avoid fragmentation.

If people doesn't find critical bugs in this version, this appears to be the end of the 3.1.x series. We'll go back to aim for 100% RFC compliance in the next update.

### 2014-04-25

Version 3.1.4 released. Fixes:

1. Two <a href="{{ site.repository-url }}/issues/90" target="_blank">kernel</a> <a href="{{ site.repository-url }}/issues/84" target="_blank">crashes</a>.
2. The userspace application now <a href="{{ site.repository-url }}/issues/86" target="_blank">resolves names</a>.
3. <a href="{{ site.repository-url }}/issues/87" target="_blank">Added support</a> for Linux 3.13+.

Also, we <a href="{{ site.repository-url }}/issues/90" target="_blank">no longer recommend usage of Jool in kernel 3.12</a>.

### 2014-03-26

Version 3.1.3 released. Fixes:

1. An <a href="{{ site.repository-url }}/issues/81" target="_blank">incorrect implementation</a> used to ban configuration on certain systems.
2. A <a href="{{ site.repository-url }}/issues/79" target="_blank">bug</a> used to prevent Jool from sending certain ICMP errors.
3. A <a href="{{ site.repository-url }}/issues/83" target="_blank">memory leak</a>.
4. Slightly optimized the packet translation algorithm by <a href="{{ site.repository-url }}/issues/69" target="_blank">replacing some spinlocks with RCUs</a>.

### 2014-03-04

Website released. *This website!*

And with it comes a new release. 3.1.2 fixes:

1. <a href="{{ site.repository-url }}/issues/76" target="_blank">21-centuried the userspace-app's installation procedure</a>.
2. <a href="{{ site.repository-url }}/issues/77" target="_blank">Jool is now more explicit regarding the suffix of prefixes</a>.
3. <a href="{{ site.repository-url }}/issues/78" target="_blank">Jool no longer wrecks itself when modprobed with invalid arguments</a>.

### 2014-02-21

Version 3.1.1 released.

It contains two bugfixes:

1. <a href="{{ site.repository-url }}/issues/75" target="_blank">Added permission checking to the admin-related userspace requests.</a>
2. <a href="{{ site.repository-url }}/issues/72" target="_blank">Fixed compatibility issues with ~3.1 kernels.</a>

### 2014-01-15

Version 3.1.0 released. Jool finally handles fragments!

Other important fixes:

* Major optimizations on both the BIB and session databases. The module should scale a lot more gracefully as clients demand more traffic.
* Jool no longer requires a separate IPv4 address.
* Kernel panic during removal of the module fixed.
* And <a href="{{ site.repository-url }}/issues?milestone=11&state=closed" target="_blank">More stuff</a>.

