---
language: en
layout: default
category: Documentation
title: OpenWRT
---

[Documentation](documentation.html) > [Installation](documentation.html#installation) > OpenWRT

# Jool in OpenWRT/LEDE

## Index

1. [Introduction](#introduction)
2. [Installing Jool](#installing-jool)

## Introduction

Compiling and installing kernel modules is not the way things are meat to be done in OpenWRT. Fortunately, the OpenWRT folks are kind enough to provide official packages for Jool. If you intend to use this distribution, please keep in mind the notes in this document while following the rest of the tutorials in the documentation.

Please also note that these binaries are not maintained nor supervised by the Jool team. We are still available for advice if issues arise, however.

And finally: It might take an indeterminate amount of time for the latest version of Jool to be uploaded to OpenWRT's repository. Remember that you can find previous versions of this site's documentation in the [download page](download.html).

## Installing Jool

You need LEDE 21.02 at least. (I tested it in 21.02.1.)

	opkg update
	opkg install kmod-jool
	opkg install jool-tools

To check Jool's version, run

	jool --version

As of 2021-11-16, that installs Jool 4.1.5.

