---
language: en
layout: default
category: Documentation
title: Userspace Applications Installation
---

[Documentation](documentation.html) > [Installation](documentation.html#installation) > Userspace Application

# Userspace Applications Installation

## Index

1. [Introduction](#introduction)
2. [Requirements](#requirements)
3. [Downloading the Code](#downloading-the-code)
3. [Compilation and Installation](#compilation-and-installation)

## Introduction

Jool is four things:

1. Two <a href="https://en.wikipedia.org/wiki/Loadable_kernel_module" target="_blank">kernel modules</a> you can hook up to Linux. One of them is the SIIT implementation and the other one is the Stateful NAT64. They have their own [installation document](mod-install.html).
2. Two <a href="https://en.wikipedia.org/wiki/User_space" target="_blank">userspace</a> applications which can be used to configure each module.

This document explains how to obtain the binaries of the userspace application.

## Requirements

### libnl-3

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Ubuntu</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
</div>

{% highlight bash %}
# apt-get install libnl-3-dev
{% endhighlight %}

{% highlight bash %}
# yum install libnl3*
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
2. The [Git repository](https://github.com/NICMx/NAT64) (Hit the "Download ZIP" button).

> ![Note!](../images/bulb.svg) The Git repository is named "NAT64" for historic reasons only. You're actually downloading both the SIIT and the NAT64.

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
$ cd NAT64-master/usr
$ ./autogen.sh
$ ./configure
$ make
# make install
{% endhighlight %}

> ![Note!](../images/bulb.svg) If you only want to compile the SIIT binary, you can speed things up by running the make commands in the `mod/stateless` folder. Similarly, if you only want the NAT64, do so in `mod/stateful`.

