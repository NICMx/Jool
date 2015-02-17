---
layout: documentation
title: Documentation - Troubleshooting/FAQ
---

# Troubleshooting/FAQ

This sums up problems we've seen users run into.

## Jool is intermitently unable to translate traffic.

Did you run something in the lines of

{% highlight bash %}
ip addr flush dev eth1
{% endhighlight %}

?

Then you might have deleted the interface's <a href="http://en.wikipedia.org/wiki/Link-local_address" target="_blank">Link address</a>.

Link addresses are used by several relevant IPv6 protocols. In particular, they are used by the *Neighbor Discovery Protocol*, which means if you don't have them, the NAT64 machine will have trouble finding its IPv6 neighbors.

Check the output of `ip addr`. 

<div class="highlight"><pre><code class="bash">user@N:~# /sbin/ip address
(...)
2: <strong>eth0</strong>: &lt;BROADCAST,MULTICAST,UP,LOWER_UP&gt; mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 08:00:27:33:65:c8 brd ff:ff:ff:ff:ff:ff
    inet6 2001:db8::1/32 <strong>scope global</strong>
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe33:65c8/64 <strong>scope link</strong>
       valid_lft forever preferred_lft forever
3: <strong>eth1</strong>: &lt;BROADCAST,MULTICAST,UP,LOWER_UP&gt; mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
    link/ether 08:00:27:33:65:c8 brd ff:ff:ff:ff:ff:ff
    inet6 2001:db8::1/32 <strong>scope global</strong>
       valid_lft forever preferred_lft forever
</code></pre></div>

The former interface is correctly configured; it has both a "scope global" address (used for typical traffic) and a "scope link" address (used for internal management). Interface _eth1_ lacks a link address, and is therefore a headache inducer.

The easiest way to restore scope link addresses, we have found, is to just reset the interface:

{% highlight bash %}
ip link set eth1 down
ip link set eth1 up
{% endhighlight %}

Yes, I'm serious:

<div class="highlight"><pre><code class="bash">user@N:~# /sbin/ip address
TODO
</code></pre></div>

Also, for future reference, keep in mind that the correct way to flush an interface is

{% highlight bash %}
ip addr flush dev eth1 scope global
{% endhighlight %}

IPv4 doesn't need link addresses.

## The throughput is terrible!

[Turn offloads off!](misc-offloading.html)

## I can't ping the IPv4 pool address.

Actually, this is normal in Jool 3.2.x and below. The destination address of the ping packet is translatable, so Jool is stealing the packet. Unfortunately, it doesn't have a relevant BIB entry (because the ping wasn't started from IPv6), so the translation is a failure (and the packet is dropped).

It looking weird aside, it doesn't cause any other catastrophes; just ping the node address.

Jool 3.3+ handles this better and the ping should succeed.

