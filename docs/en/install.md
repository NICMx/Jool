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
2. [Updating your system](#updating-your-system)
2. [Installing Dependencies](#installing-dependencies)
3. [Downloading the Code](#downloading-the-code)
4. [Compilation and Installation](#compilation-and-installation)
5. [Uninstalling](#uninstalling)

## Introduction

A full installation of Jool is eleven binaries:

- [Kernel modules](https://en.wikipedia.org/wiki/Loadable_kernel_module):
	- `jool.ko`, `jool_siit.ko` and `jool_common.ko`: The Stateful NAT64, the SIIT and the functionality that is shared between the previous two. They are the actual translators and do most of the work.
- [Userspace](https://en.wikipedia.org/wiki/User_space) tools:
	- `jool` and `jool_siit`: Two console clients which can be used to configure the modules above.
	- `joold`: An userspace daemon that can synchronize state between different NAT64 Jool instances.
- Userspace libraries:
	- `libxt_JOOL.so` and `libxt_JOOL_SIIT.so`: Two shared objects that enable Jool-themed iptables rules.
	- `libjoolargp.la`, `libjoolnl.la` and `libjoolutil.la` (extensions may vary): Three shared libraries containing common functionality for the other userspace components.

This document will explain how to compile and install all of that on most Linux distributions.

In following console segments, `$` indicates the command can be executed freely; `#` means it requires admin privileges.

## Updating your system

This is not always necessary, but aside from fetching security patches, it maximizes the probability of easily acquiring the proper kernel headers later.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Debian</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
</div>

<!-- Debian -->
{% highlight bash %}
user@T:~# apt update
user@T:~# apt upgrade
{% endhighlight %}

<!-- CentOS -->
{% highlight bash %}
user@T:~# yum update
 
{% endhighlight %}

If you got a new kernel, best load it:

{% highlight bash %}
user@T:~# /sbin/reboot
{% endhighlight %}

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
	<span class="distro-selector" onclick="showDistro(this);">CentOS (older versions)</span>
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

<!-- CentOS (Older versions) -->
{% highlight bash %}
Try downloading the corresponding rpms:
https://rpmfind.net/linux/rpm2html/search.php?query=kernel-headers
https://rpmfind.net/linux/rpm2html/search.php?query=kernel-devel
(recall that your kernel version is `uname -r`)
then do
user@T:~# rpm -ivh *.rpm
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
user@T:~# apt install git autoconf libtool
{% endhighlight %}

<!-- CentOS -->
{% highlight bash %}
user@T:~# yum install git automake libtool
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
$ wget {{ site.downloads-url-2 }}/v{{ site.latest-version }}/jool-{{ site.latest-version }}.tar.gz
$ tar -xzf jool-{{ site.latest-version }}.tar.gz
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

## Uninstalling

### Userspace Clients

Simply run `make uninstall` in the directory where you compiled them:

```bash
user@T:~$ cd jool-{{ site.latest-version }}/
user@T:~# make uninstall
```

If you no longer have the directory where you compiled them, download it again and do this instead:

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">tarball</span>
	<span class="distro-selector" onclick="showDistro(this);">git clone</span>
</div>

<!-- tarball -->
```bash
user@T:~$ cd jool-{{ site.latest-version }}/
user@T:~$
user@T:~$ ./configure
user@T:~# make uninstall
```

<!-- git clone -->
```bash
user@T:~$ cd Jool/
user@T:~$ ./autogen.sh
user@T:~$ ./configure
user@T:~# make uninstall
```

### Kernel Modules (if installed by DKMS)

Use `dkms remove`. Here's an example in which I'm trying to remove version 4.0.1:

```bash
$ dkms status
jool, 4.0.1.git.v4.0.1, 4.15.0-54-generic, x86_64: built
jool, 4.0.6.git.v4.0.6, 4.15.0-54-generic, x86_64: installed
$
$ sudo dkms remove jool/4.0.1.git.v4.0.1 --all

-------- Uninstall Beginning --------
Module:  jool
Version: 4.0.1.git.v4.0.1
Kernel:  4.15.0-54-generic (x86_64)
-------------------------------------

Status: This module version was INACTIVE for this kernel.
depmod...

DKMS: uninstall completed.

------------------------------
Deleting module version: 4.0.1.git.v4.0.1
completely from the DKMS tree.
------------------------------
Done.
$
$ dkms status
jool, 4.0.6.git.v4.0.6, 4.15.0-54-generic, x86_64: installed
```

### Kernel Modules (if installed by Kbuild in accordance with old documentation)

Delete the `.ko` files and re-index by way of `depmod`:

```bash
$ sudo rm /lib/modules/$(uname -r)/extra/jool_siit.ko
$ sudo rm /lib/modules/$(uname -r)/extra/jool.ko
$ sudo depmod
```
