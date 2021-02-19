---
language: en
layout: default
category: Documentation
title: OpenWRT
---

[Documentation](documentation.html) > [Installation](documentation.html#installation) > OpenWRT

# Jool in OpenWRT/LEDE

> ![Warning!](../images/warning.svg) **WARNING!**
> 
> At time of writing, OpenWRT's "official" Jool package has been unmaintained since December 2016. It'll apparently be stuck in version 3.5.7 forever. I'm sorry; we don't have any control over it whatsoever.
> 
> You can find the old 3.5 documentation [here](https://github.com/NICMx/releases/raw/master/Jool/Jool-3.5-doc.zip).
> 
> A more up-to-date version of Jool is actually in fact available in OpenWRT, but it lives as a member of a community-maintained (but still "official," by some definition of "official" I don't quite grasp) package "feed." To install the new version, I understand that you have to [compile a new OpenWRT image](https://openwrt.org/docs/guide-developer/build-system/install-buildsystem), while [enabling the "packages" feed definitions](https://github.com/openwrt/packages).
> 
> Assuming you want to install the "packages" feed, the only part of this document I think still applies to you is [Using Jool](#using-jool). Sorry; I don't really know much about OpenWRT, so that's all I can tell you with relative certainty.

## Index

1. [Introduction](#introduction)
2. [Installing Jool](#installing-jool)
3. [Using Jool](#using-jool)

## Introduction

Compiling and installing kernel modules is not the way things are meat to be done in OpenWRT. Fortunately, the OpenWRT folks are kind enough to provide official packages for Jool. If you intend to use this distribution, please keep in mind the notes in this document while following the rest of the tutorials in the documentation.

Please also note that these binaries are not maintained nor supervised by the Jool team. We are still available for advice if issues arise, however.

And finally: It might take an indeterminate amount of time for the latest version of Jool to be uploaded to OpenWRT's repository. Remember that you can find previous versions of this site's documentation in the [download page](download.html).

## Installing Jool

> ![Warning!](../images/warning.svg) If you have somehow previously installed Jool from source in your machine, then those binaries may conflict with the ones installed here.
>
> You may uninstall source-installed binaries by following [these steps](install.html#uninstalling).

You need LEDE 17.01 at least. I tested it in LEDE-17.01.1, but newer is better, of course.

	opkg update
	opkg install kmod-jool
	opkg install jool-tools

That's it as far as installation goes.

## Using Jool

There's one significant caveat when using the module: OpenWRT's `modprobe` is rather lacking in features. There are alternatives, however:

1. `insmod` is the proper way of saying `/sbin/modprobe --first-time`.
2. `rmmod` is the proper way of saying `/sbin/modprobe -r`.

So when Jool's documentation asks you to issue a command such as the following:

	/sbin/modprobe --first-time jool pool6=64:ff9b::/96

Run this instead:

	insmod jool pool6=64:ff9b::/96

And instead of this:

	/sbin/modprobe -r jool

Do this:

	rmmod jool

With this in mind, you should be ready to tackle the [basic tutorials](documentation.html#basic-tutorials).

