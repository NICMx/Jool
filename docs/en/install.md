---
language: en
layout: default
category: Documentation
title: Installation
---

[Documentation](documentation.html) > [Installation](documentation.html#installation) > Other distros

# Jool Installation

## Index

1. [Introduction](#introduction)
2. [Installing Dependencies](#installing-dependencies)
3. [Downloading the Code](#downloading-the-code)
4. [Compilation and Installation](#compilation-and-installation)

## Introduction

Jool is seven binaries:

- Two [kernel modules](https://en.wikipedia.org/wiki/Loadable_kernel_module) you can hook up to Linux. One of them is the SIIT implementation and the other one is the Stateful NAT64. They are the translating components and do most of the work.
- Two [userspace](https://en.wikipedia.org/wiki/User_space) clients which can be used to configure each module.
- Two shared objects that iptables uses to enable `ip[6]tables -j JOOL[_SIIT]`-style rules.
- An optional userspace daemon that can synchronize state between different NAT64 Jool instances.

This document will explain how to compile and install all of that on most Linux distributions.

In following console segments, `$` indicates the command can be executed freely; `#` means it requires admin privileges.

## Installing Dependencies

> Note: Distros sometimes change this, and it's difficult to keep it updated. You might need to tweak dependency installation to some extent.
> 
> Please [report](https://github.com/NICMx/Jool/issues) any issues you find. (Including instructions for different distributions.)

You need a kernel that is [supported](intro-jool.html#compatibility) by the version of Jool that you're using.

Aside from that, you will need your build essentials. Some distributions already ship them by default, so omit this step in those cases.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Debian</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
	<span class="distro-selector" onclick="showDistro(this);">Arch Linux</span>
	<span class="distro-selector" onclick="showDistro(this);">openSUSE</span>
	<span class="distro-selector" onclick="showDistro(this);">Ubuntu Server</span>
</div>

<!-- TODO pkg-config in other distros -->

<!-- Debian -->
{% highlight bash %}
user@T:~# apt install build-essential pkg-config
{% endhighlight %}

<!-- CentOS -->
{% highlight bash %}
user@T:~# yum install gcc
{% endhighlight %}

<!-- Arch Linux -->
{% highlight bash %}
user@T:~# pacman -S base-devel
{% endhighlight %}

<!-- openSUSE -->
{% highlight bash %}
user@T:~# zypper install gcc make
{% endhighlight %}

<!-- Ubuntu Server -->
{% highlight bash %}
user@T:~# apt install gcc make
{% endhighlight %}

The modules need your kernel headers:

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Ubuntu/Debian</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
	<span class="distro-selector" onclick="showDistro(this);">openSUSE</span>
	<span class="distro-selector" onclick="showDistro(this);">Raspberry Pi</span>
</div>

<!-- Ubuntu/Debian -->
{% highlight bash %}
user@T:~# apt install linux-headers-$(uname -r)
{% endhighlight %}

<!-- CentOS -->
{% highlight bash %}
user@T:~# yum install kernel-devel
user@T:~# yum install kernel-headers
{% endhighlight %}

<!-- openSUSE -->
{% highlight bash %}
user@T:~# zypper install kernel-source
{% endhighlight %}

<!-- Raspberry Pi -->
{% highlight bash %}
user@T:~$ # See {{ site.repository-url }}/issues/158
{% endhighlight %}

The userspace clients and the daemon need the [Development Library and Headers for libnl-genl-3](http://www.infradead.org/~tgr/libnl/):

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Debian/Ubuntu</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
</div>

<!-- Debian/Ubuntu -->
{% highlight bash %}
user@T:~# apt install libnl-genl-3-dev
{% endhighlight %}

<!-- CentOS -->
{% highlight bash %}
user@T:~# yum install libnl3-devel
{% endhighlight %}

The iptables shared object needs the [Netfilter xtables Library development files](http://www.netfilter.org/):

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Debian/Ubuntu 18.04</span>
	<span class="distro-selector" onclick="showDistro(this);">Ubuntu 16.04</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
</div>

<!-- Debian/Ubuntu 18.04 -->
{% highlight bash %}
user@T:~# apt install libxtables-dev
{% endhighlight %}

<!-- Ubuntu 16.04 -->
{% highlight bash %}
user@T:~# apt install iptables-dev
{% endhighlight %}

<!-- CentOS -->
{% highlight bash %}
user@T:~# yum install iptables-devel
{% endhighlight %}

You also want DKMS, for automatic module rebuild during kernel updates:

{% highlight bash %}
user@T:~# apt install dkms
{% endhighlight %}

If you're going to clone the git repository, you need git and the autotools:

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Ubuntu</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
</div>

<!-- Ubuntu -->
{% highlight bash %}
user@T:~# apt install git autoconf
{% endhighlight %}

<!-- CentOS -->
{% highlight bash %}
user@T:~# yum install git automake
{% endhighlight %}

And if you don't, you will need a `.tar.gz` extraction tool:

{% highlight bash %}
user@T:~# apt install tar
{% endhighlight %}

## Downloading the Code

You have two options:

1. Official tarballs hosted at [Downloads](download.html).
2. Cloning the [Git repository]({{ site.repository-url }}).

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">tarballs</span>
	<span class="distro-selector" onclick="showDistro(this);">git clone</span>
</div>

<!-- tarballs -->
{% highlight bash %}
$ wget {{ site.downloads-url-2 }}/v{{ site.latest-version }}/jool_{{ site.latest-version }}.tar.gz
$ tar -xzf jool_{{ site.latest-version }}.tar.gz
{% endhighlight %}

<!-- git clone -->
{% highlight bash %}
$ git clone https://github.com/NICMx/Jool.git
 
{% endhighlight %}

The repository version sometimes includes slight bugfixes not present in the latest official tarball, which you can access by sticking to the latest commit of the `master` branch. (Tarballs and `master` are considered stable, other branches are development.)

## Compilation and Installation

The kernel modules and the userspace applications need to be compiled and installed separately.

This is how you compile and install the kernel modules:

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">tarball</span>
	<span class="distro-selector" onclick="showDistro(this);">git clone</span>
</div>

<!-- tarball -->
{% highlight bash %}
user@T:~# dkms install jool-{{ site.latest-version }}/
{% endhighlight %}

<!-- git clone -->
{% highlight bash %}
user@T:~# dkms install Jool/
{% endhighlight %}

And this is how you compile and install the userspace applications:

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">tarball</span>
	<span class="distro-selector" onclick="showDistro(this);">git clone</span>
</div>

<!-- tarball -->
{% highlight bash %}
user@T:~$ cd jool-{{ site.latest-version }}/
user@T:~$
user@T:~$ ./configure
user@T:~$ make
user@T:~# make install
{% endhighlight %}

<!-- git clone -->
{% highlight bash %}
user@T:~$ cd Jool/
user@T:~$ ./autogen.sh
user@T:~$ ./configure
user@T:~$ make
user@T:~# make install
{% endhighlight %}
