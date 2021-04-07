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
	1. [Method 1: Installing OpenWRT's official package](#method-1-installing-openwrts-official-package)
	2. [Method 2: Installing the "packages" feed](#method-2-installing-the-packages-feed)

## Introduction

Compiling and installing kernel modules is not the way things are meat to be done in OpenWRT. Fortunately, the OpenWRT folks are kind enough to provide official packages for Jool. If you intend to use this distribution, please keep in mind the notes in this document while following the rest of the tutorials in the documentation.

Please also note that these binaries are not maintained nor supervised by the Jool team. We are still available for advice if issues arise, however.

And finally: It might take an indeterminate amount of time for the latest version of Jool to be uploaded to OpenWRT's repository. Remember that you can find previous versions of this site's documentation in the [download page](download.html).

## Installing Jool

### Method 1: Installing OpenWRT's official package

> ![Warning!](../images/warning.svg) As of April 2021, this method installs Jool 3.5.7, which is very old.
> 
> Please note that Jool 3.5.7 and the current Jool ({{ site.latest-version }}) are very different beasts. All other tutorials on this site employ the {{ site.latest-version}} syntax, and so few of them will work with 3.5.7.
> 
> You can download a snapshot of the old 3.5 documentation [here](https://github.com/NICMx/releases/raw/master/Jool/Jool-3.5-doc.zip).

You need LEDE 17.01 at least. (I tested it in LEDE-17.01.1, as well as 19.07.7.)

	opkg update
	opkg install kmod-jool
	opkg install jool-tools

To check Jool's version, run

	jool --version

If that prints 3.5.7, then again, ignore the rest of this site; refer to the [old documentation](https://github.com/NICMx/releases/raw/master/Jool/Jool-3.5-doc.zip) instead.

### Method 2: Installing the "packages" feed

OpenWRT "feeds" are community-maintained groups of packages. The feed that happens to be named "[packages](https://github.com/openwrt/packages)" has, for several years, been diligent in maintaining an up-to-date version of Jool.

Though it gives you a recent Jool, installing package feeds is somewhat involved. You have to compile a new OpenWRT image (by following [these steps](https://openwrt.org/docs/guide-developer/quickstart-build-images)), making sure to enable the feed "packages" in step 2.3, and then Jool in step 3.

Here's a summarized recipe. Tested in 2021-04-06. It assumes you're compiling in Debian or a derivative:

```bash
# Download dependencies.
sudo apt update
sudo apt install build-essential ccache ecj fastjar file g++ gawk \
	gettext git java-propose-classpath libelf-dev libncurses5-dev \
	libncursesw5-dev libssl-dev python python2.7-dev python3 unzip wget \
	python3-distutils python3-setuptools rsync subversion swig time \
	xsltproc zlib1g-dev

# Get the OpenWRT code.
git clone https://git.openwrt.org/openwrt/openwrt.git
cd openwrt

# Enable the "packages" feed.
scripts/feeds update packages
scripts/feeds install -p packages jool

# Configure your image.
# (You need to specify your hardware in this menu.
# Unfortunately, I can't help you, because I don't have your hardware.
# Try finding it in the database, and read its notes: https://openwrt.org/toh/start )
# Also enable "Network" -> "jool-tools"
# Also enable "Kernel modules" -> "Network Support" -> "kmod-jool"
make menuconfig

# Compile.
# (This takes between 60 and 130 minutes in my PC.)
make
```

That's it. The image file is at `bin/targets/<something>/<something>/`; flash it like normal. Jool will be already installed.

