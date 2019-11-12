---
language: en
layout: default
category: Documentation
title: Debian
---

[Documentation](documentation.html) > [Installation](documentation.html#installation) > Debian

# Jool in Debian and its Derivatives

If you're using a flavor of Debian, you have three options: Installing the _Debian Release_, the _Standalone Package_ or compiling from source.

Here's a comparison between the three:

| | Debian Release | Standalone Package | Source |
|-|----------------|------------|--------|
| Available in Debian | yes | yes | yes |
| Available in some of Debian's derivatives<br />(such as Ubuntu) | no | yes | yes |
| Available in the amd64 architecture | yes | yes | yes |
| Available in other architectures | yes | no | yes |
| Automatic updates (through Debian) | yes | no | no |
| Latest version always available | no `*` | yes | yes |

The Debian Release belongs to the [`unstable` Debian release branch](https://wiki.debian.org/DebianUnstable). For the time being, Jool is stuck in there due to being a recent addition to Debian. Please note that adding `unstable` to your sources puts your entire system in bleeding edge territory; If this is an issue for you, consider apt pinning or the other options.

`*` After an official Jool release, its corresponding latest Debian Release might take up to a few days to be approved and served by Debian.

This document explains how to install the Debian Release and the Standalone Package. To compile from source, visit [this page](install.html).

## Uninstalling old versions (installed from source)

> Skip this step if you've never installed Jool from source in your target machine.

If you already installed a previous version of Jool from source, know that it will conflict with the userspace clients installed in the next section. To uninstall the old userspace clients, run `make uninstall` in the directory where you compiled them:

```bash
user@T:~$ cd jool-4.0.5/
user@T:~# make uninstall
```

If you no longer have the directory where you compiled it, download it again and do this instead:

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">tarball</span>
	<span class="distro-selector" onclick="showDistro(this);">git clone</span>
</div>

<!-- iptables Jool -->
```bash
user@T:~$ cd jool-4.0.5/
user@T:~$
user@T:~$ ./configure
user@T:~# make uninstall
```

<!-- Netfilter Jool -->
```bash
user@T:~$ cd Jool/
user@T:~$ ./autogen.sh
user@T:~$ ./configure
user@T:~# make uninstall
```

This can be done before or after the commands in the next section. (But if you did it later, restart your terminal.)

## Installing the Debian packages

Make sure you have your current kernel headers:

```bash
user@T:~# apt install linux-headers-$(uname -r)
```

Then choose whether you want the Debian Release or the Standalone Package:

### Debian Release

Add `unstable` to your sources list then install like any other formal Debian package:

```bash
user@T:~# nano /etc/apt/sources.list # Add "deb <URL> unstable main"
user@T:~# apt update
user@T:~# apt install jool-dkms jool-tools
```

### Standalone Package

Download the standalone `.deb` packages from [Downloads](download.html) and install them like so:

```bash
user@T:~# apt install ./jool-dkms_{{ site.latest-version }}-1_all.deb ./jool-tools_{{ site.latest-version }}-1_amd64.deb
```

These have been tested in Debian 10 and Ubuntu 18.04.

Here's a quick link back to the [basic tutorials list](documentation.html#basic-tutorials).
