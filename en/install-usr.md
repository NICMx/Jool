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

Jool is four things:

1. Two <a href="https://en.wikipedia.org/wiki/Loadable_kernel_module" target="_blank">kernel modules</a> you can hook up to Linux. One of them is the SIIT implementation and the other one is the Stateful NAT64. They have their own [installation document](install-mod.html).
2. Two <a href="https://en.wikipedia.org/wiki/User_space" target="_blank">userspace</a> applications which can be used to configure each module.

This document explains how to obtain the binaries of the userspace application.

## Requirements

### libnl-genl-3

{% highlight bash %}
# apt-get install libnl-genl-3-dev
{% endhighlight %}

### Autoconf

You only need this if you plan on downloading the Github version of Jool.

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
2. The [Git repository]({{ site.repository-url }}) ("Clone or download" > "Download ZIP").

> ![Note!](../images/bulb.svg) The name of the Git repository was recently renamed from "NAT64" to "Jool". Old "NAT64" content should now redirect to "Jool" so this shouldn't be too confusing.

## Compilation and Installation

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

