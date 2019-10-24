---
language: en
layout: default
category: Documentation
title: Debian
---

[Documentation](documentation.html) > [Installation](documentation.html#installation) > Debian

# Jool in Debian and its derivatives

<!--
The Debian package is maintained by the Jool team. It should always be up-to-date.

## Installation

{% highlight bash %}
$ sudo apt install jool-dkms jool-tools
{% endhighlight %}
-->

## Uninstalling old versions (installed from source)

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
{% highlight bash %}
user@T:~$ cd jool-4.0.5/
user@T:~$
user@T:~$ ./configure
user@T:~# make uninstall
{% endhighlight %}

<!-- Netfilter Jool -->
{% highlight bash %}
user@T:~$ cd Jool/
user@T:~$ ./autogen.sh
user@T:~$ ./configure
user@T:~# make uninstall
{% endhighlight %}

This can be done before or after the commands in the next section. (But if you did it later, restart your terminal.)

You might also want to detach the old running modules while you're at it:

```bash
user@T:~# modprobe -r jool_siit
user@T:~# modprobe -r jool
```

## Installing the Debian packages

The official Debian package is currently [queued for approval into `unstable`](https://github.com/NICMx/Jool/issues/243#issuecomment-517779741). In the meantime, if you're using amd64, you can download standalone `.deb` packages from [Downloads](#downloads.html) and install them like so:

{% highlight bash %}
user@T:~# apt install ./jool-dkms_{{ site.latest-version }}-1_all.deb ./jool-tools_{{ site.latest-version }}-1_amd64.deb
{% endhighlight %}

> Sorry; I can't provide packages for other architectures because I don't have any hardware to try them on. If you'd like to help, [contact us](contact.html).

They are tested in Debian 10 and Ubuntu 18.04.

Please note that these packages do not update automatically. This feature will not be available until Jool reaches `unstable`.

Here's a quick link back to the [basic tutorials list](documentation.html#basic-tutorials).
