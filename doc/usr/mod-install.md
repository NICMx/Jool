---
layout: documentation
title: Documentation - Kernel Modules Installation
---

[Documentation](doc-index.html) > [Installation](doc-index.html#installation) > Kernel module

# Kernel Modules Installation

## Index

1. [Introduction](#introduction)
2. [Requirements](#requirements)
3. [Compilation](#compilation)
4. [Installation](#installation)

## Introduction

Jool is four things:

1. Two <a href="https://en.wikipedia.org/wiki/Loadable_kernel_module" target="_blank">kernel modules</a> you can hook up to the Linux kernel. One of them is a stateless translator and the other one is a stateful translator. They are the main components and all you need to get started; this document explains how to install them.
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

If you're just getting acquainted with NAT64, some people have an easier time picturing the ordeal when the translator has two separate network interfaces (one to interact with IPv6 networks, one for IPv4 networks). This is not a requirement; you can get away with only one interface (by dual stacking on it), and you can also have more than one per protocol. This is possible because figuring out which interface should a packet be dispatched through is routing's problem, which is already well implemented in the kernel.

Because the tutorials are first and foremost a tool to get newcomers on the right mindset, most of the deployment discussion will assume two separate interfaces (exemplified below: eth0 and eth1).

{% highlight bash %}
$ /sbin/ip link show
(...)
2: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:3d:24:77 brd ff:ff:ff:ff:ff:ff
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:ca:18:c8 brd ff:ff:ff:ff:ff:ff
{% endhighlight %}

Finally, you need your kernel headers. If you're using apt-get, just run this:

{% highlight bash %}
$ apt-get install linux-headers-$(uname -r)
{% endhighlight %}

## Compilation

Each kernel version combined with each different architecture requires different binaries, so providing packages for every combination would be impossibly cumbersome. For this reason, what you'll download is the source; there is no way around compiling the code yourself.

On the flip side, kernel modules cannot have dependencies other than your kernel headers and a good compiler, so the procedure is fairly painless.

To download Jool, you have two options:

* Official releases are hosted in the [Download page](download.html). These will prove less convoluted when you're installing the userspace application.
* There's the <a href="https://github.com/NICMx/NAT64" target="_blank">Github repository</a>. This might have slight bugfixes not present in the latest official release, which you can access by sticking to the latest commit of the master branch (in case you're wondering, we do all the risky development elsewhere).

You might be used to a standard three-step procedure to compile and install programs: `./configure && make && make install`. Kernel modules do not follow it, but have a special one on their own.

As far as the compilation goes, there is no `configure` script. But you also don't have to edit the Makefile; you jump straight to `make` and you're done. The global Makefile can be found in the `mod` folder:

{% highlight bash %}
user@node:~$ unzip Jool-<version>.zip
user@node:~$ cd Jool-<version>/mod
user@node:~/Jool-<version>/mod$ make
{% endhighlight %}

That will compile both the stateful and the stateless binaries. If, for some reason, you don't want to compile the both of them, just say so:

{% highlight bash %}
user@node:~/Jool-<version>/mod$ make stateless
or
user@node:~/Jool-<version>/mod$ make stateful
{% endhighlight %}

And that's that.

## Installation

You copy the binaries generated to your system's module pool by running the `modules_install` target:

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

You'll later activate the module using the `modprobe` command. Thing is, the fact that the module resides in your pool doesn't mean it has already been indexed. Use `depmod` to make `modprobe` aware of the new module:

{% highlight bash %}
user@node:~# /sbin/depmod
{% endhighlight %}

Done; Jool can now be started. In order to run it, head to [Basic Runs](mod-runs.html).

