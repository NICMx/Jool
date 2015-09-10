---
language: en
layout: default
category: Documentation
title: Kernel Modules Installation
---

[Documentation](documentation.html) > [Installation](documentation.html#installation) > Kernel module

# Kernel Modules Installation

## Index

1. [Introduction](#introduction)
2. [Requirements](#requirements)
	1. [Valid kernels](#valid-kernels)
	2. [Build Essentials](#build-essentials)
	2. [Kernel Headers](#kernel-headers)
	3. [Network interfaces](#network-interfaces)
	4. [DKMS](#dkms)
	5. [Ethtool](#ethtool)
3. [Downloading the Code](#downloading-the-code)
3. [Compilation and Installation](#compilation-and-installation)
	1. [Installation via DKMS](#installation-via-dkms)
	2. [Installation via Kbuild](#installation-via--kbuild)

## Introduction

Jool is four binaries:

1. Two [kernel modules](https://en.wikipedia.org/wiki/Loadable_kernel_module) you can hook up to Linux. One of them is the SIIT implementation and the other is the Stateful NAT64. They are the translating components and all you need to get started; this document explains how to install them.
2. Two [userspace](https://en.wikipedia.org/wiki/User_space) applications which can be used to configure each module. They have their own [installation document](usr-install.html).

## Requirements

Because The are so many different Linux versions out there, distributing the modules' binaries is not feasible; you need to compile them yourself.

(In following console segments, `$` indicates the command can be executed freely; `#` means it requites admin privileges.)

### Valid kernels

Jool supports kernels starting from Linux 3.0. Use `uname -r` to know your kernel version.

{% highlight bash %}
$ /bin/uname -r
3.5.0-45-generic
$ # OK, fine.
{% endhighlight %}

### Build Essentials

Several distributions already include them; omit this step in those cases.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Debian</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
	<span class="distro-selector" onclick="showDistro(this);">Arch Linux</span>
	<span class="distro-selector" onclick="showDistro(this);">openSUSE</span>
</div>

<!-- Debian -->
{% highlight bash %}
# apt-get install build-essential
{% endhighlight %}

<!-- CentOS -->
{% highlight bash %}
# yum install gcc
{% endhighlight %}

<!-- Arch Linux -->
{% highlight bash %}
# pacman -S base-devel
{% endhighlight %}

<!-- openSUSE -->
{% highlight bash %}
# zypper install gcc make
{% endhighlight %}

### Kernel headers

All kernel modules depend on them; they tell Jool the parameters Linux was compiled with. Most distros host them in their repositories.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Ubuntu/Debian</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
	<span class="distro-selector" onclick="showDistro(this);">openSUSE</span>
	<span class="distro-selector" onclick="showDistro(this);">Raspberry Pi</span>
</div>

<!-- Ubuntu/Debian -->
{% highlight bash %}
# apt-get install linux-headers-$(uname -r)
{% endhighlight %}

<!-- CentOS -->
{% highlight bash %}
# yum install kernel-devel
# yum install kernel-headers
{% endhighlight %}

<!-- openSUSE -->
{% highlight bash %}
# zypper install kernel-source
{% endhighlight %}

<!-- Raspberry Pi -->
{% highlight bash %}
$ # See https://github.com/NICMx/NAT64/issues/158
{% endhighlight %}

### Network interfaces

[Translating packets using only one interface is possible](mod-run-alternate.html), but two (one for IPv4, one for IPv6) is more intuitive.

Therefore, if you're using these documents for educational purposes, two interfaces are recommended:

{% highlight bash %}
$ /sbin/ip link show
(...)
2: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:3d:24:77 brd ff:ff:ff:ff:ff:ff
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:ca:18:c8 brd ff:ff:ff:ff:ff:ff
{% endhighlight %}

### DKMS

DKMS is a framework for kernel module management. It's optional but recommended (reasons at [Compilation and Installation](#compilation-and-installation)).

{% highlight bash %}
# apt-get install dkms
{% endhighlight %}

## Getting the code

You have two options:

1. Official releases are hosted in the [Download page](download.html).  
These will prove less convoluted when you install the userspace application.
2. There's the <a href="https://github.com/NICMx/NAT64" target="_blank">Github repository</a>.  
This might have slight bugfixes not present in the latest official release, which you can access by sticking to the latest commit of the master branch (we do all the risky development elsewhere).

## Compilation and Installation

You might be used to a standard three-step procedure to compile and install programs: `./configure && make && make install`. Kernel modules do not follow it, but have a special one on their own called Kbuild.

If your distribution supports the Dynamic Kernel Module Support (DKMS) framework, this can be used in order to compile and build the Jool kernel modules. If however your distribution does not support DKMS, or its use is undesired for some reason, the Jool kernel modules can be built and installed manually by using the Kbuild system directly.

Regardless of which method you use to install the kernel modules, after a successfull installation you will be able to start Jool using `modprobe jool` or `modprobe jool_siit`. The logical next step after that would be to read the [Basic SIIT Tutorial](mod-run-vanilla.html).

### Installation via DKMS

The DKMS framework provides a convenient wrapper around the standard kernel Kbuild system. A single DKMS command will perform all the steps necessary in order to use third-party kernel modules such as Jool. It will also ensure that everything is done all over again whenever necessary (such as after a kernel upgrade). DKMS can also be used to create packages for deb/rpm-based distributions containing pre-built Jool kernel modules.

In order to install the Jool kernel modules using DKMS, you need to run `dkms install /path/to/Jool-sourcedir`, like so:

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Official version</span>
	<span class="distro-selector" onclick="showDistro(this);">Github version</span>
</div>

{% highlight bash %}
$ unzip Jool-<version>.zip
# dkms install Jool-<version>
{% endhighlight %}

{% highlight bash %}
$ unzip NAT64-master.zip
# dkms install NAT64-master
{% endhighlight %}

DKMS will now have compiled, installed and indexed the Jool kernel modules; Jool is now ready for use.

### Installation via Kbuild

Kbuild is the Linux kernel's standard system for compiling and installing kernel modules. Jool comes with native Kbuild support.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Official version</span>
	<span class="distro-selector" onclick="showDistro(this);">Github version</span>
</div>

{% highlight bash %}
$ unzip Jool-<version>.zip
$ cd Jool-<version>/mod
$ make
# make install
{% endhighlight %}

{% highlight bash %}
$ unzip NAT64-master.zip
$ cd NAT64-master/mod
$ make
# make install
{% endhighlight %}

> **Warning!**
> 
> Kernels 3.7 and up want you to sign your kernel modules to make sure you're loading them in a responsible manner.
> 
> But if your kernel was not configured to _require_ this feature (the kernels of many distros don't), you won't have much of an issue here. The output of `make install` will output "Can't read private key"; this looks like an error, but is actually a warning, <a href="https://github.com/NICMx/NAT64/issues/94#issuecomment-45248942" target="_blank">so you can continue the installation peacefully</a>.
> 
> Sorry; if your kernel _was_ compiled to require module signing, you probably know what you're doing, so I'll skip the instructions to make that work.

