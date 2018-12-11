---
language: en
layout: default
category: Documentation
title: OpenWRT
---

[Documentation](documentation.html) > [Installation](documentation.html#installation) > OpenWRT

# Jool in OpenWRT/LEDE

Compiling and installing kernel modules is not the way things are meat to be done in OpenWRT. Fortunately, the OpenWRT folks are kind enough to provide official packages for Jool. If you intend to use this distribution, please keep in mind the notes in this document while following the rest of the tutorials in the documentation.

Please also note that these binaries are not maintained nor supervised by the Jool team. We are still available for advice if issues arise, however.

And finally: It might take an indeterminate amount of time for the latest version of Jool to be uploaded to OpenWRT's repository. Remember that you can find previous versions of this site's documentation in the [download page](download.html).

## Installing Jool

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

With this in mind, you should be ready to tackle the [basic tutorials](http://jool.mx/en/documentation.html#basic-tutorials).

