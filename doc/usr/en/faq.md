---
layout: faq
title: Documentation - Troubleshooting/FAQ
---

[Documentation](doc-index.html) > [Miscellaneous](doc-index.html#miscellaneous) > FAQ

# Troubleshooting/FAQ

This sums up problems we've seen users run into.

## I modprobed Jool but it doesn't seem to be doing anything.

Modprobing Jool without enough arguments is legal. It will assume you intend to finish configuring using the userspace app, and sit idle until you've done so.

Use the userspace app's [`--global`](usr-flags-global.html#description) flag to figure out Jool's status:

{% highlight bash %}
$ jool_siit --global
  Status: Disabled
{% endhighlight %}

{% highlight bash %}
$ jool --global
  Status: Disabled
{% endhighlight %}

SIIT Jool's minimum configuration requirements are

- A prefix in the [IPv6 pool](usr-flags-pool6.html) **or** at least one entry in the [EAM table](usr-flags-eamt.html).
- You must have not [manually disabled](usr-flags-global.html#enable---disable) it.

Stateful Jool's minimum configuration requirements are

- At least one prefix in the [IPv6 pool](usr-flags-pool6.html).
- At least one prefix/address in the [IPv4 pool](usr-flags-pool4.html).
- You must have not [manually disabled](usr-flags-global.html#enable---disable) it.

If that doesn't seem to be the problem, try the [logs](logging.html).

## What do I do with this error message? It's horribly ambiguous.

This happens if your text terminal is not listening to kernel messages of error severity.

The jist of it is, if a problem with the incoming configuration is detected in kernelspace, Jool doesn't send the friendly version of the error message to the userspace application [because it's lazy](https://github.com/NICMx/NAT64/issues/169). Instead, it writes it in the kernel logs. The userspace application is then stuck with a generic Unix error code, and that's what it reports to the user.

[Run `dmesg` or one of its variats to query the kernel logs](logging.html), as shown in the [issue report](https://github.com/NICMx/NAT64/issues/169).

## Jool is intermitently unable to translate traffic.

Did you run something in the lines of

{% highlight bash %}
ip addr flush dev eth1
{% endhighlight %}

?

Then you might have deleted the interface's <a href="http://en.wikipedia.org/wiki/Link-local_address" target="_blank">Link address</a>.

Link addresses are used by several relevant IPv6 protocols. In particular, they are used by the *Neighbor Discovery Protocol*, which means if you don't have them, the translating machine will have trouble finding its IPv6 neighbors.

Check the output of `ip addr`. 

<div class="highlight"><pre><code class="bash">user@T:~$ /sbin/ip address
1: lo: &lt;LOOPBACK,UP,LOWER_UP&gt; mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: <strong>eth0</strong>: &lt;BROADCAST,MULTICAST,UP,LOWER_UP&gt; mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 08:00:27:83:d9:40 brd ff:ff:ff:ff:ff:ff
    inet6 2001:db8:aaaa::1/64 <strong>scope global</strong> 
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe83:d940/64 <strong>scope link</strong> 
       valid_lft forever preferred_lft forever
3: <strong>eth1</strong>: &lt;BROADCAST,MULTICAST,UP,LOWER_UP&gt; mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 08:00:27:c6:01:48 brd ff:ff:ff:ff:ff:ff
    inet6 2001:db8:bbbb::1/64 <strong>scope global</strong> tentative 
       valid_lft forever preferred_lft forever
</code></pre></div>

Interface _eth0_ is correctly configured; it has both a "scope global" address (used for typical traffic) and a "scope link" address (used for internal management). Interface _eth1_ lacks a link address, and is therefore a headache inducer.

The easiest way to restore scope link addresses, we have found, is to just reset the interface:

{% highlight bash %}
ip link set eth1 down
ip link set eth1 up
{% endhighlight %}

Yes, I'm serious:

<div class="highlight"><pre><code class="bash">user@T:~$ /sbin/ip address
1: lo: &lt;LOOPBACK,UP,LOWER_UP&gt; mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: &lt;BROADCAST,MULTICAST,UP,LOWER_UP&gt; mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 08:00:27:83:d9:40 brd ff:ff:ff:ff:ff:ff
    inet6 2001:db8:aaaa::1/64 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe83:d940/64 scope link 
       valid_lft forever preferred_lft forever
3: eth1: &lt;BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 08:00:27:c6:01:48 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::a00:27ff:fec6:148/64 <strong>scope link</strong> 
       valid_lft forever preferred_lft forever
</code></pre></div>

(Note, you need to add the global address again)

Also, for future reference, keep in mind that the "correct" way to flush an interface is

{% highlight bash %}
ip addr flush dev eth1 scope global
{% endhighlight %}

IPv4 doesn't need link addresses that much.

## The throughput is terrible!

[Turn offloads off!](misc-offloading.html)

If you're running Jool in a guest virtual machine, something important to keep in mind is that you might rather or also have to disable offloads in the [VM host](http://en.wikipedia.org/wiki/Hypervisor)'s uplink interface.

## I can't ping the IPv4 pool address.

Actually, this is normal in Jool 3.2.x and below. The destination address of the ping packet is translatable, so Jool is stealing the packet. Unfortunately, it doesn't have a relevant BIB entry (because the ping wasn't started from IPv6), so the translation is a failure (and the packet is dropped).

It looking weird aside, it doesn't cause any other catastrophes; just ping the node address.

Jool 3.3+ handles this better and the ping should succeed.

