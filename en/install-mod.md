---
language: en
layout: default
category: Documentation
title: Kernel Modules Installation
---

[Documentation](documentation.html) > [Installation](documentation.html#installation) > Kernel modules

# Kernel Modules Installation

## Index

1. [Introduction](#introduction)
2. [Requirements](#requirements)
3. [Downloading the Code](#downloading-the-code)
3. [Compilation and Installation](#compilation-and-installation)
	1. [Installation via DKMS](#installation-via-dkms)
	2. [Installation via Kbuild](#installation-via-kbuild)

## Introduction

Jool is four binaries:

1. Two [kernel modules](https://en.wikipedia.org/wiki/Loadable_kernel_module) you can hook up to Linux. One of them is the SIIT implementation and the other is the Stateful NAT64. They are the translating components and all you need to get started; this document explains how to install them.
2. Two [userspace](https://en.wikipedia.org/wiki/User_space) applications which can be used to configure each module. They have their own [installation document](install-usr.html).

## Requirements

Because The are so many different Linux versions out there, distributing the modules' binaries is not feasible; you need to compile them yourself.

(In following console segments, `$` indicates the command can be executed freely; `#` means it requites admin privileges.)

### Valid kernels

Jool supports kernels starting from Linux 3.2. Use `uname -r` to know your kernel version.

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
$ # See {{ site.repository-url }}/issues/158
{% endhighlight %}

### Network interfaces

[Translating packets using only one interface is possible](single-interface.html), but two (one for IPv4, one for IPv6) is more intuitive.

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

DKMS is a framework for kernel module management. It is optional but recommended (reasons at [Compilation and Installation](#compilation-and-installation)).

{% highlight bash %}
# apt-get install dkms
{% endhighlight %}

## Downloading the Code

You have two options:

1. Official releases are hosted in the [Download page](download.html).  
These will prove less convoluted when you install the userspace application.
2. There's the [Git repository]({{ site.repository-url }}) ("Clone or download" > "Download ZIP").  
This might have slight bugfixes not present in the latest official release, which you can access by sticking to the latest commit of the master branch (we do all the risky development elsewhere).

> ![Note!](../images/bulb.svg) The name of the Git repository was recently renamed from "NAT64" to "Jool". Old "NAT64" content should now redirect to "Jool" so this shouldn't be too confusing.

## Compilation and Installation

You have two options: Kbuild and DKMS.

Kbuild is the bare bones module building infrastructure, and (as long as your kernel was compiled with kernel module support) your system most likely already has it.

On the other hand, DKMS is recommended because it is far more robust. It allows creating packages for deb/rpm-based distributions containing pre-built kernel modules, handles recompiling the binaries whenever the kernel gets updated, and has a well-documented uninstallation mechanism.

<!-- TODO If DKMS allows deb/rpm-based distributions, we have no excuse not to publish these in the downloads page... -->

### Installation via DKMS

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Official release</span>
	<span class="distro-selector" onclick="showDistro(this);">Git version</span>
</div>

{% highlight bash %}
$ unzip Jool-<version>.zip
# dkms install Jool-<version>
{% endhighlight %}

{% highlight bash %}
$ unzip master.zip
# dkms install Jool-master
{% endhighlight %}

### Installation via Kbuild

> ![!](../images/warning.svg) Keep in mind: Module binaries **depend** on kernel version. The binaries generated here will become obsolete when you update your kernel. If you insist on using Kbuild, you need to recompile/reinstall Jool yourself whenever this happens.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Official release</span>
	<span class="distro-selector" onclick="showDistro(this);">Git version</span>
</div>

{% highlight bash %}
$ unzip Jool-<version>.zip
$ cd Jool-<version>/mod
$ make
# make install
{% endhighlight %}

{% highlight bash %}
$ unzip master.zip
$ cd Jool-master/mod
$ make
# make install
{% endhighlight %}

> ![!](../images/warning.svg) Kernels 3.7 and up want you to sign your kernel modules to make sure you're loading them in a responsible manner.
> 
> But if your kernel was not configured to _require_ this feature (the kernels of many distros don't), you won't have much of an issue here. The output of `make install` will output "Can't read private key"; this looks like an error, but is actually a warning, so you can continue the installation peacefully.
> 
> Sorry; if your kernel _was_ compiled to require module signing, you probably know what you're doing, so I'll skip the instructions to make that work.

> ![Note!](../images/bulb.svg) If you only want to compile the SIIT binary, you can speed things up by running the make commands in the `mod/stateless` folder. Similarly, if you only want the NAT64, do so in `mod/stateful`.

