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
3. [Installation](#installation)
   1. [DKMS](#dkms)
   2. [Kbuild](#kbuild)

## Introduction

Jool is four things:

1. Two <a href="https://en.wikipedia.org/wiki/Loadable_kernel_module" target="_blank">kernel modules</a> you can hook up to Linux. One of them is the SIIT implementation and the other one is the Stateful NAT64. They are the main components and all you need to get started; this document explains how to install them.
2. Two <a href="https://en.wikipedia.org/wiki/User_space" target="_blank">userspace</a> applications which can be used to configure each module. They have their own [installation document](usr-install.html).

When you put it that way, there is really nothing unusual about Jool's installation. But I figure some of our users might have no previous experience meddling with drivers, so this overview will serve as an introduction to at least give them an idea of what each step does.

## Requirements

First off, the computer that will be translating traffic needs a kernel (again, Linux) whose version is 3.0 to 3.15. Higher versions are probably fine, but we haven't tested them. We do not recommend using Linux 3.12 because of the reasons outlined <a href="https://github.com/NICMx/NAT64/issues/90" target="_blank">here</a>.

Use the `uname -r` command to know your kernel version.

{% highlight bash %}
$ /bin/uname -r
3.5.0-45-generic
$ # OK, fine.
{% endhighlight %}

If you're just getting acquainted with IPv4/IPv6 Translation, some people have an easier time picturing the ordeal when the translator has two separate network interfaces (one to interact with IPv6 networks, one for IPv4 networks). This is not a requirement; you can get away with only one interface (by [dual stacking](mod-run-alternate.html) on it), and you can also have more than one per protocol. This is possible because figuring out which interface should a packet be dispatched through is routing's problem, which is already well implemented in the kernel.

Because the tutorials are first and foremost a tool to get newcomers on the right mindset, most of the deployment discussion will assume two separate interfaces (exemplified below: eth0 and eth1).

{% highlight bash %}
$ /sbin/ip link show
(...)
2: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:3d:24:77 brd ff:ff:ff:ff:ff:ff
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:ca:18:c8 brd ff:ff:ff:ff:ff:ff
{% endhighlight %}

Finally, you need the dependencies. Pick whichever works for you...

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Ubuntu</span>
	<span class="distro-selector" onclick="showDistro(this);">Debian</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
	<span class="distro-selector" onclick="showDistro(this);">Arch Linux</span>
	<span class="distro-selector" onclick="showDistro(this);">openSUSE</span>
	<span class="distro-selector" onclick="showDistro(this);">Raspberry Pi</span>
</div>

<!-- Ubuntu -->
{% highlight bash %}
# apt-get install linux-headers-$(uname -r)
{% endhighlight %}

<!-- Debian -->
{% highlight bash %}
# apt-get install build-essential
# apt-get install linux-headers-$(uname -r)
{% endhighlight %}

<!-- CentOS -->
{% highlight bash %}
# yum install kernel-devel
# yum install kernel-headers
# yum install gcc
{% endhighlight %}

<!-- Arch Linux -->
{% highlight bash %}
# pacman -S base-devel
{% endhighlight %}

<!-- openSUSE -->
{% highlight bash %}
# zypper install gcc make
# zypper install kernel-source
{% endhighlight %}

<!-- Raspberry Pi -->
{% highlight bash %}
$ # see https://github.com/NICMx/NAT64/issues/158
{% endhighlight %}

## Installation

Each kernel version combined with each different architecture requires different binaries, so providing packages for every combination would be impossibly cumbersome. For this reason, what you'll download is the source; there is no way around compiling the code yourself.

On the flip side, kernel modules cannot have dependencies other than your kernel headers and a good compiler, so the procedure is fairly painless.

To download Jool, you have two options:

* Official releases are hosted in the [Download page](download.html). These will prove less convoluted when you're installing the userspace application.
* There's the <a href="https://github.com/NICMx/NAT64" target="_blank">Github repository</a>. This might have slight bugfixes not present in the latest official release, which you can access by sticking to the latest commit of the master branch (in case you're wondering, we do all the risky development elsewhere).

You might be used to a standard three-step procedure to compile and install programs: `./configure && make && make install`. Kernel modules do not follow it, but have a special one on their own called Kbuild.

If your distribution supports the Dynamic Kernel Module Support (DKMS) framework, this can be used in order to compile and build the Jool kernel modules. If however your distribution does not support DKMS, or its use is undesired for some reason, the Jool kernel modules can be built and installed manually by using the Kbuild system directly.

Regardless of which method you use to install the kernel modules, after a successfull installation you will be able to start Jool using `modprobe jool` or `modprobe jool_siit`. The logical next step after that would be to read the [Basic SIIT Tutorial](mod-run-vanilla.html).

### DKMS

The DKMS framework provides a convenient wrapper around the standard kernel Kbuild system. A single DKMS command will perform all the steps necessary in order to use third-party kernel modules such as Jool. It will also ensure that everything is done all over again whenever necessary (such as after a kernel upgrade). DKMS can also be used to create packages for deb/rpm-based distributions containing pre-built Jool kernel modules.

In order to install the Jool kernel modules using DKMS, you need to run `dkms install /path/to/Jool-sourcedir`, like so:

{% highlight bash %}
user@node:~# apt-get install dkms
user@node:~$ unzip Jool-<version>.zip
user@node:~# dkms install Jool-<version>
{% endhighlight %}

DKMS will now have compiled, installed and indexed the Jool kernel modules; Jool is now ready for use.

### Kbuild

Kbuild is the Linux kernel's standard system for compiling and installing kernel modules. Jool comes with native Kbuild support. As far as the compilation goes, there is no `configure` script. But you also don't have to edit the Makefile; you jump straight to `make` and you're done. The global Makefile can be found in the `mod` folder:

{% highlight bash %}
user@node:~$ unzip Jool-<version>.zip
user@node:~$ cd Jool-<version>/mod
user@node:~/Jool-<version>/mod$ make
{% endhighlight %}

The Jool kernel modules are now compiled for your current kernel. Next, copy them to your system's module pool by running the `modules_install` target:

{% highlight bash %}
user@node:~/Jool-<version>/mod# make modules_install
{% endhighlight %}

> **Warning!**
> 
> Kernels 3.7 and up want you to sign your kernel modules to make sure you're loading them in a responsible manner.
> 
> But if your kernel was not configured to _require_ this feature (the kernels of many distros don't), you won't have much of an issue here. The output of `make modules_install` will output "Can't read private key"; this looks like an error, but is actually a warning, <a href="https://github.com/NICMx/NAT64/issues/94#issuecomment-45248942" target="_blank">so you can continue the installation peacefully</a>.
> 
> Sorry; if your kernel _was_ compiled to require module signing, you probably know what you're doing, so I'll skip the instructions to make that work.

You'll later activate the modules using the `modprobe` command. Thing is, the fact that they reside in your pool doesn't mean they have already been indexed. Use `depmod` to make `modprobe` aware of the new modules:

{% highlight bash %}
user@node:~# /sbin/depmod
{% endhighlight %}
