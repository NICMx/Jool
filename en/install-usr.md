---
language: en
layout: default
category: Documentation
title: Userspace Applications Installation
---

[Documentation](documentation.html) > [Installation](documentation.html#installation) > Userspace Applications

# Userspace Applications Installation

## Index

1. [Introduction](#introduction)
2. [Requirements](#requirements)
3. [Downloading the Code](#downloading-the-code)
3. [Compilation and Installation](#compilation-and-installation)

## Introduction

Jool is five things:

1. Two <a href="https://en.wikipedia.org/wiki/Loadable_kernel_module" target="_blank">kernel modules</a> you can hook up to Linux. One of them is the SIIT implementation and the other one is the Stateful NAT64. They have their own [installation document](install-mod.html).
2. Two <a href="https://en.wikipedia.org/wiki/User_space" target="_blank">userspace</a> applications which can be used to configure each module.
3. One userspace daemon used to synchronize sessions between different Jool kernel modules.

This document explains how to obtain the binaries of the userspace applications and the daemon.

## Requirements

### Build Essentials

You don't need pkg-config if you know what you're doing.

{% highlight bash %}
# apt-get install gcc make pkg-config
{% endhighlight %}

### libnl-genl-3

{% highlight bash %}
# apt-get install libnl-genl-3-dev
{% endhighlight %}

### Autoconf

You only need this if you downloaded the Github version of Jool.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Ubuntu</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
</div>

{% highlight bash %}
# apt-get install autoconf
{% endhighlight %}

{% highlight bash %}
# yum install automake
{% endhighlight %}

## Downloading the Code

Pick either:

1. The Official Releases' [Download page](download.html).
2. The [Git repository]({{ site.repository-url }}). Either
	- hit the "Clone or download" button and then "Download ZIP",
	- or execute `git clone https://github.com/NICMx/Jool.git`.

> ![Note!](../images/bulb.svg) The Git repository was recently renamed from "NAT64" to "Jool". Links to the old name should be automatically redirected to the new one so this shouldn’t be too confusing.

## Compilation and Installation

> ![Note!](../images/bulb.svg) [Add `LIBNLGENL3_CFLAGS` and `LIBNLGENL3_LIBS` to `configure`](https://github.com/NICMx/Jool/issues/228) if you chose not to install pkg-config.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Official release</span>
	<span class="distro-selector" onclick="showDistro(this);">Git version</span>
</div>

{% highlight bash %}
$ unzip Jool-<version>.zip
$ cd Jool-<version>/usr
$
$ ./configure
$ make
# make install
{% endhighlight %}

{% highlight bash %}
$ unzip master.zip
$ cd Jool-master/usr
$ ./autogen.sh
$ ./configure
$ make
# make install
{% endhighlight %}

> ![Note!](../images/bulb.svg) If you only want to compile the SIIT binary, you can speed things up by running the make commands in the `usr/stateless` folder. If you want the NAT64 client instead, do so in `usr/stateful`. If you want the daemon, go to `usr/joold`.

