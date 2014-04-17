---
layout: documentation
title: Documentation - Offloading
---

# The problem with Offloading

## Index

1. [Theory](#theory)
2. [Practice](#practice)

## Theory

Offloading is a technique meant to optimize network throughput. Born from the observation that a single large packet is significantly faster to process than several small ones, the idea is to combine several of them from a common stream on reception, and then pretend, to the eyes of the rest of the system, that the new packet was the one received from the cord all along.

Here's an example for the visual-oriented. This is how packets are normally processed (no offloading):

![Fig.1 - No offload](images/offload-none.svg)

(For the moment, assume the Internet layer holds IPv4.)

There are two streams here. The yellow one consists of three very small packets:

1. 1st packet: bytes 0 through 9.
2. 2nd packet: bytes 10 to 29.
3. 3rd packet: bytes 30 to 39.

And the blue one has somewhat larger packets:

1. bytes 0 to 599
2. bytes 600 to 1199
3. bytes 1200 to 1799

There are several ways to implement offloading. Pictured below is a simplified version of what a NIC could perhaps do, rather than the above:

![Fig.2 - Offload done right](images/offload-right.svg)

Simply put, several contiguous packets are merged together into an equivalent, larger one. The card could for example do this by merging IP fragments or even TCP segments (even if TCP sits two layers above). It doesn't matter as long as the change can be seen as completely transparent as far as the transfer of data is concerned.

And yes, we're now dealing with heavier pieces of data, but truth be told, most of the Internet and Transport layers' activity lies in the first few bytes of each packet (i.e. headers). So we mostly get to process n packets for the price of one.

This is all fine and dandy, but you start running into trouble when the system is supposed to forward the data (rather than just consuming it). Say the hardware has a <a href="https://en.wikipedia.org/wiki/Maximum_transmission_unit" target="_blank">Maximum Transmission Unit (MTU)</a> of 1500; this is what happens:

![Fig.3 - Offload on a router](images/offload-router.svg)

In step 1 the aggregation happens, which makes step 2 very fast, but then because the assembled packet of the blue stream is too big for the outgoing interface (size 1800 > max 1500), the packet gets fragmented in step 3, which is inefficient.

More importantly, if the emitter performed <a href="http://en.wikipedia.org/wiki/Path_MTU_Discovery" target="_blank">path MTU discovery</a>, then the optimum MTU computed will be lost in step 1 (because it is not stored in the packet; it is indicated by its size, which step 1 mangles). If the Don't Fragment flag of the IPv4 header is _not_ set, then this will encourage further re-fragmentation. But if the flag IS set, then the packet will be eventually and irremediably dropped as soon as it reaches a lower MTU. Hence, we just created a black hole.

(Well, not completely. A number of conditions are required for the NIC to run offloading. These conditions might rarely and randomly not be met, so certain packets will occasionally not be aggregated, and as such will slip past the hole. If your transport protocol retries enough, instead of having a complete denial of service, you get an extremely - **EXTREMELY** - slow network.)

When the forwarding machine is an IPv6 router (or, in Jool's case, a NAT64 translating from IPv4 to 6), this is more immediately a problem because _IPv6 routers are not supposed to fragment packets_ (they are expected to just drop the packet and return an ICMP error message). So your packet will be lost in step 3 _even if the Don't Fragment flag of the original packet was not set_.

And that's it. Offloading for leaf nodes is great, offloading for routers is trouble.

## Practice

So, if you want to run Jool, you want to turn off offloading. This is how we start doing it (your mileage might vary):

{% highlight bash %}
$ sudo apt-get install ethtool
{% endhighlight %}

Then apply this to every relevant interface:

{% highlight bash %}
$ sudo ethtool --offload [your interface here] gro off
{% endhighlight %}

"gro" is "Generic Receive Offload". Perhaps it's simply because our kernels don't support them, but we currently don't know for sure why we don't also have to turn off lro (Large receive offload), gso (Generic segmentation offload) and perhaps others (see `man ethtool`). If you're not sure, I'd say playing safe would equal getting rid of every variant you see:

{% highlight bash %}
$ sudo ethtool --offload [your interface here] tso off
$ sudo ethtool --offload [your interface here] ufo off
$ sudo ethtool --offload [your interface here] gso off
$ sudo ethtool --offload [your interface here] gro off
$ sudo ethtool --offload [your interface here] lro off
{% endhighlight %}

(If you can shed more light into the subject, please let us know - [jool@nic.mx](mailto:jool@nic.mx).)

Sometimes ethtool claims it cannot change some of the variants, but keep in mind this is usually because it is not supported and hence it wasn't on in the first place. Have a look at your configuration using

{% highlight bash %}
$ sudo ethtool --show-offload [your interface here]
{% endhighlight %}

Cheers!

