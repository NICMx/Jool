---
language: en
layout: default
category: Documentation
title: Logging
---

[Documentation](documentation.html) > [Miscellaneous](documentation.html#miscellaneous) > Logging

# Logging

If Jool has something to say, it will do so in the kernel logs (just like any other kernel component). Typical ways to find this include

- Running `dmesg`.
- `cat`ting `/var/log/syslog`.
- In your console, [as long as it's listening to kernel messages](http://unix.stackexchange.com/a/13023).

Thankfully, Linux is generally silent after booting, so Jool's latest messages should be found at the very bottom.

Jool uses four levels in the severity spectrum (see `dmesg --help`):

1. err: "Your configuration cannot be applied, user". This only happens during module insertion/removal and as a response of userspace application requests. These messages are also sent over to the userspace application so it can print them in stderr.
2. warn: "Are you sure this configuration is sane? I'm going to keep doing this, but it doesn't look like it's going places". Only happens during packet translations.
3. info: "The kernel module was inserted", "the kernel module was removed". Also [`logging-bib`](usr-flags-global.html#logging-bib) and [`logging-session`](usr-flags-global.html#logging-session)'s exploits.
4. debug: "And now I'm doing this". "I couldn't translate this packet because X, and I think it's normal".

Debug messages are normally compiled out of Jool's binaries because they are lots and can slow things down. If you are testing or troubleshooting however, they can be of help.

If you want Jool to print debug messages, follow these steps:

## 1. Uninstall your current modules

Do one of the following:

- If you used some package, just remove the package (eg. `apt remove jool-dkms`).
- If you used DKMS, follow [these steps](install.html#kernel-modules-if-installed-by-dkms).
- If you used Kbuild, follow [these steps](install.html#kernel-modules-if-installed-by-kbuild-in-accordance-with-old-documentation). (At the bottom.)

## 2. Recompile, including the -DDEBUG flag

Go to the `dkms.conf` file found in the root of the source package.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">tarball</span>
	<span class="distro-selector" onclick="showDistro(this);">git clone</span>
</div>

<!-- tarball -->
{% highlight bash %}
user@T:~$ cd jool-{{ site.latest-version }}/
user@T:~$ nano dkms.conf
{% endhighlight %}

<!-- git clone -->
{% highlight bash %}
user@T:~$ cd Jool/
user@T:~$ nano dkms.conf
{% endhighlight %}

Change

	MAKE[0]="make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build/src/mod/common modules \
	      && make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build/src/mod/nat64 modules \
	      && make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build/src/mod/siit modules"

Into

	MAKE[0]="make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build/src/mod/common JOOL_FLAGS=-DDEBUG modules \
	      && make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build/src/mod/nat64 JOOL_FLAGS=-DDEBUG modules \
	      && make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build/src/mod/siit JOOL_FLAGS=-DDEBUG modules"

Then install the module via DKMS:

```bash
user@T:~# dkms install .
```

## 3. Restart and reconfigure you Jool instance(s)

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">jool</span>
	<span class="distro-selector" onclick="showDistro(this);">jool_siit</span>
</div>

<!-- tarball -->
{% highlight bash %}
modprobe -r jool
modprobe jool
jool instance add ...
{% endhighlight %}

<!-- git clone -->
{% highlight bash %}
modprobe -r jool_siit
modprobe jool_siit
jool_siit instance add ...
{% endhighlight %}

## 4. Notice the log noise

	$ dmesg | tail -5
	[ 3465.639622] ===============================================
	[ 3465.639655] Catching IPv4 packet: 192.0.2.16->198.51.100.8
	[ 3465.639724] Translating the Packet.
	[ 3465.639756] Address 192.0.2.16 lacks an EAMT entry and there's no pool6 prefix.
	[ 3465.639806] Returning the packet to the kernel.

These messages quickly add up. If your computer is storing them, make sure you revert the binaries (by removing `-DDEBUG` and reinstalling) when you're done so they stop flooding your disk.

If `dmesg` is not printing the messages, try tweaking its `--console-level`. Have a look at `man dmesg` for details.
