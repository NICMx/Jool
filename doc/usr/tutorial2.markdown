---
layout: documentation
title: Documentation - Tutorial 2
---

# Tutorial 2: Basic Runs

## Index

1. [Introduction](#introduction)
2. [Scenario 1: Dumb & Minimalistic](#scenario-1-dumb--minimalistic)
3. [Scenario 2: Single interface](#scenario-2-single-interface)
4. [Scenario 3: Brains](#scenario-3-brains)

## Introduction

The purpose of this tutorial is twofold: To show how the translation mechanism is supposed to be activated and to tune up the user's understanding of how a stateful NAT64 interacts with other nodes so he or she can adapt it to different network arrangements.

You might want to get acquainted with the <a href="https://linux.die.net/man/8/ip" target="_blank">ip</a> command before you continue.

## Scenario 1: Dumb & Minimalistic

This first setup will focus on explaining the steps needed to insert Jool to the kernel. The network configuration, on the other hand, will get in the way as little as possible, especially so the module can be seen running without dedicated or special equipment. Better network configurations will be covered in the other scenarios.

Say you want to upgrade your network to IPv6-only (i. e. you can't afford to <a href="https://en.wikipedia.org/wiki/Dual-stack#Dual_IP_stack_implementation" target="_blank">dual-stack</a> on every involved machine) and you still want access to the IPv4 Internet.

Your situation will probably look like this:

![Fig.1 - Initial state](images/tut2.1-prestate.svg)

I'm going to over-simplify this, and assume your network and the Internet are a single computer each. We'll configure the network manually, and there will be no DNS.

![Fig.2 - Simplified initial state](images/tut2.1-simplification.svg)

This will also minimize your pain if you're just becoming acquainted with Jool, since you will only need three boxes, all of which can be simple laptops.

In order to deploy NAT64, throw the Jool machine in-between:

![Fig.3 - Dual-stack Linux in between.](images/tut2.1-setup.svg)

Again, the second interface is not really neccesary; you will see a single interface dual-stacking in the [second scenario](#scenario-2-single-interface). Note that one of the interfaces is wireless, because that's how most laptops are today.

Also, as part of the simplification, I'm going to allow myself to make B both of the other nodes' default gateways. Again, less brain-dead options will be covered later.

Nodes A and C do not need to be Linux, but the commands displayed below assume that they are.

### Network on Node B

If your distro features a network manager, you want to turn it off because we don't want it to interfere. Your mileage might vary on how to do this.

{% highlight bash %}
user@B:~# # This is how I do it in Ubuntu.
user@B:~# service network-manager stop
user@B:~# ip address flush dev eth0 && ip -6 address flush dev wlan0
{% endhighlight %}

Now configure the cord. Note that there's nothing unusual about this; we haven't gotten into Jool territory yet. Run the following commands on node B:

{% highlight bash %}
user@B:~# /sbin/ip link set eth0 up
user@B:~# /sbin/ip link set wlan0 up
user@B:~#
user@B:~# /sbin/ip -6 address add 2001:db8::1/32 dev eth0
user@B:~#
user@B:~# # Create a wireless network so Node A can find us
user@B:~# # (Note, we only have to do this because we chose to use
user@B:~# # a wireless interface, see the diagram).
user@B:~# /sbin/iwconfig wlan0 mode Ad-hoc essid jool
user@B:~#
user@B:~# /sbin/ip address add 192.0.2.1/24 dev wlan0
{% endhighlight %}

### Network on Node C

Run the following commands on C:

{% highlight bash %}
user@C:~# service network-manager stop
user@C:~# /sbin/ip link set eth0 up
user@C:~# /sbin/ip -6 address add 2001:db8::2/32 dev eth0
user@C:~# /sbin/ip -6 route add default via 2001:db8::1 dev eth0
{% endhighlight %}

### Network on Node A

Run the following commands on A:

{% highlight bash %}
user@A:~# service network-manager stop
user@A:~# /sbin/ip link set wlan0 up
user@A:~# /sbin/ip address add 192.0.2.2/24 dev wlan0
user@A:~# /sbin/ip route add default via 192.0.2.1 dev wlan0
user@A:~# /sbin/iwconfig wlan0 mode Ad-hoc essid jool
{% endhighlight %}

Note that nodes A and C still have no way to interact with each other. You might want to `/bin/ping` A with B, and also `/bin/ping6` B with C to make sure you're on the right track.

### NAT64 on Node B

The network is out of the way now, so let's get cracking with Jool:

First, turn node B into a router. In and of itself, NAT64 is just the packet translation mechanism; everything routing-related is taken from Linux's existing functionality. So if node B needs to know where it should be forwarding stuff, enable it:

{% highlight bash %}
user@B:~# sysctl -w net.ipv4.conf.all.forwarding=1
user@B:~# sysctl -w net.ipv6.conf.all.forwarding=1
{% endhighlight %}

We've come to realize enabling forwarding does not get you rid of <a href="http://en.wikipedia.org/wiki/Large_receive_offload" target="_blank">offloading</a>. Though it does add too much functionality to routers for comfort, offloading is particularly hazardous in an IPv6-featuring environment since IPv6 routers are not expected to reassemble or create fragments ([click here](offloading.html) for a more thorough explanation). So if your equipment supports it, you want to disable it; by running the following commands you might massively improve performance.

{% highlight bash %}
user@B:~# ethtool --offload eth0 tso off
user@B:~# ethtool --offload eth0 ufo off
user@B:~# ethtool --offload eth0 gso off
user@B:~# ethtool --offload eth0 gro off
user@B:~# ethtool --offload eth0 lro off
user@B:~# ethtool --offload wlan0 tso off
user@B:~# ethtool --offload wlan0 ufo off
user@B:~# ethtool --offload wlan0 gso off
user@B:~# ethtool --offload wlan0 gro off
user@B:~# ethtool --offload wlan0 lro off
{% endhighlight %}

(If it complains it cannot change something, keep in mind it can already be off; run `sudo ethtool --show-offload [interface]` to figure it out.)

Finally, the RFC demands us to get rid of martian packets (even if it didn't, it's still a good idea). We didn't include it in Jool itself since it comes, often by default, in Linux itself.

{% highlight bash %}
user@B:~# sysctl -w net.ipv4.conf.all.log_martians=1
(TODO hey, that looks like it only applies to IPv4)
{% endhighlight %}

And we're done. The following command will stick Jool to your Kernel.

{% highlight bash %}
user@B:~# /sbin/modprobe jool
{% endhighlight %}

You know you've done everything correctly if you can `ping6` from node C to node A using the prefix + node A's address as the target IPv6 address (You _cannot_ contact C from A unless you create [static bindings](static-bindings.html)).

{% highlight bash %}
user@C:~$ ping6 64:ff9b::192.0.2.2
PING 64:ff9b::192.0.2.2(64:ff9b::c000:202) 56 data bytes
64 bytes from 64:ff9b::c000:202: icmp_seq=1 ttl=63 time=3.66 ms
64 bytes from 64:ff9b::c000:202: icmp_seq=2 ttl=63 time=2.53 ms
64 bytes from 64:ff9b::c000:202: icmp_seq=3 ttl=63 time=3.28 ms
64 bytes from 64:ff9b::c000:202: icmp_seq=4 ttl=63 time=2.49 ms
^C
--- 64:ff9b::192.0.2.2 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3008ms
rtt min/avg/max/mdev = 2.498/2.996/3.666/0.497 ms
{% endhighlight %}

If you know your network sniffing, you can see packets being translated on node B:

![Fig.15 - Wireshark output](images/tut2.1-wireshark.png)

[Here's the libpcap file](download/tut2.1-wireshark.wsk).

If you publish a server on node A, you can see it from C as well:

![Fig.16 - Translated HTTP messages](images/tut2.1-website.png)

To shut down Jool, revert the modprobe using the `-r` flag:

{% highlight bash %}
user@B:~# /sbin/modprobe -r jool
{% endhighlight %}

### Explanation

So what is going on?

1. Node C creates a packet for someone called "64:ff9b::192.0.2.2". It can tell it doesn't belong to its own network, so the packet is sent to its default gateway, node B.
2. Node B then realizes the destination address contains the NAT64 prefix so Jool gets to process it. Among several modifications it does to the layer 3 and layer 4 headers, it strips the prefix from the destination and sets one from its own pool as the source. The result is a packet that goes to 192.0.2.2 from (say) 192.168.2.1. (192.168.2.1 is part of Jool's default pool, which we didn't edit)
3. Completely unaware of the translation, node C answers what it perceives as your average IPv4 packet. Thus a response from 192.0.2.2 to 192.168.2.1 is born.
4. Node B again realizes that the destination address belongs to one of its pools, so before any routing happens Jool gets to meddle with the packet.
Jool _remembers_ that C previously wrote to someone who ended up being 192.0.2.2, so it infers the new packet is the response to that. As such, it forwards the data to C.
5. Again completely unaware of the translation, node C receives the answer as if nothing weird just happened.

You might realize that all of this is possible because "192.0.2.2" is encoded inside of "64:ff9b::192.0.2.2". This being the case, you can also draw the conclusion that node A cannot be the one who starts the communication, since "64:ff9b::192.0.2.2" cannot be encoded inside of "192.0.2.2" and also Jool wouldn't be able to _remember_ a mapping of addresses that never happened.

And then you might want to realize that I just explained NAT to you, except with IPv6 in one side of the equation. Hence "NAT-six-four".

## Scenario 2: Single interface

This scenario is here only to tell you that if you want B to dual-stack on the same interface, you're still covered.

![Fig.3 - Single interface NAT64](images/tut2.2-one-dual.svg)

This is B's configuration:

{% highlight bash %}
user@B:~# service network-manager stop
user@B:~# /sbin/ip link set eth0 up
user@B:~# /sbin/ip -6 address add 2001:db8::1/64 dev eth0
user@B:~# /sbin/ip address add 192.0.2.1/24 dev eth0
{% endhighlight %}

This is A's configuration:

{% highlight bash %}
user@A:~# service network-manager stop
user@A:~# /sbin/ip link set eth0 up
user@A:~# /sbin/ip address add 192.0.2.2/24 dev eth0
user@A:~# /sbin/ip route add default via 192.0.2.1 dev eth0
{% endhighlight %}

Both C's configuration and the NAT64 insertion are the same as in scenario 1.

So basically, A and C share a cord, but they still can't talk because they don't speak the same language. That is, unless they ask B to translate their little chat:

{% highlight bash %}
user@C:~$ /bin/ping6 64:ff9b::192.0.2.2
PING 64:ff9b::192.168.0.2(64:ff9b::c0a8:2) 56 data bytes
64 bytes from 64:ff9b::c0a8:2: icmp_seq=1 ttl=63 time=3.03 ms
64 bytes from 64:ff9b::c0a8:2: icmp_seq=1 ttl=63 time=2.02 ms
64 bytes from 64:ff9b::c0a8:2: icmp_seq=1 ttl=63 time=2.67 ms
64 bytes from 64:ff9b::c0a8:2: icmp_seq=1 ttl=63 time=8.09 ms
^C
--- 64:ff9b::192.168.0.2 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3007ms
rtt min/avg/max/mdev = 2.022/3.956/8.099/2.419 ms
{% endhighlight %}

## Scenario 3: Brains

The configuration in [scenario 1](#scenario-1-dumb--minimalistic) was designed with speed and low resources in mind. Though several commands were issued to Linux, Jool was modprobed with no arguments and then it wasn't further tweaked. Also, the Jool machine was a stock laptop, and I don't expect to see many of those deployed as border nodes.

In this third scenario a slightly more realistic scenario will be covered, along with more thorough insight and control.

![Fig.1 - Network design](images/tut2.3-network.svg)

I dropped again the wireless interface (for realism and to clear the tutorial of iwconfig), threw in more sensible addresses (in particular, the IPv4 pool is no longer an alien, though that isn't immediately apparent in the diagram), and made each network more than one node each (but they will still all be Linux, since I'm more comfortable with its routing than anything else's). Also, I will assume that you have no control over the IPv4 nodes so we can no longer configure them in unnatural ways (In the previous tutorial, Jool was the IPv4 node's default gateway, which made no sense). If the IPv6 side is your network and the other side is your IPv4 ISP, then this is probably the case.

This tutorial will still not meddle with the DNS, and more or less as a consequence, the environment will still not be connected to the real IPv6 Internet. I've decided to move that to a [separate tutorial](tutorial4.html), because that no longer has much to do with Jool and people already familiar with DNS64 can skip it.

In case it isn't obvious, the name "J" comes from "Jool", but the "J" in the diagram is not Jool; it is the node _wearing_ Jool. When you read "J" think of the actual computer, and when you read "Jool" think of the kernel module.

We will still configure everything statically. If your distribution features a network manager, **you probably want to turn if off on every node before you issue any commands mentioned below**.

## Configuration

### Routers

Long story short: If a packet's destination address belongs to one of the pools, then Jool translates the packet. Otherwise Linux handles it normally.

If your setup is not connected to the IPv6 Internet, you can think of the NAT64 as a normal NAT where the IPv6 network is the hidden one. Nodes in network 2001:db8:2::/64 can perceive J as their default gateway, so you **might** run this on R:

{% highlight bash %}
user@R:~# /sbin/ip link set eth0 up
user@R:~# /sbin/ip link set eth1 up
user@R:~# 
user@R:~# /sbin/ip -6 address add 2001:db8:1::1/64 dev eth0
user@R:~# /sbin/ip -6 address add 2001:db8:2::1/64 dev eth1
user@R:~# 
user@R:~# # Turn R into a router.
user@R:~# /sbin/sysctl -w net.ipv6.conf.all.forwarding=1
user@R:~# 
user@R:~# # Forward unknown traffic to J.
user@R:~# # (We know the entire IPv6 Internet.
user@R:~# # Unknown traffic is probably headed to IPv4.)
user@R:~# /sbin/ip -6 route add default via 2001:db8:2::2 dev eth1
{% endhighlight %}

Of course, when you connect your network to the IPv6 Internet the NAT64 will not be the default gateway. You know that only packets whose prefix is 64::/96 are meant to be translated (i. e. the entire IPv4 Internet can be seen as a single network named "64::/96"), so in the meantime you can drop everything else:

{% highlight bash %}
user@R:~# # Use this instead of the default gateway instruction.
user@R:~# /sbin/ip -6 route add 64::/96 via 2001:db8:2::2 dev eth1
{% endhighlight %}

IPv4 routers simply need to be aware of J's IPv4 addresses. In this case, they belong to the same network, so no magic is needed here.

The configuration of S (your ISP's router) will probably look something like this. Note the complete unawareness of the fact that J holds Jool, or anything out of the ordinary for that matter:

{% highlight bash %}
user@S:~# /sbin/ip link set eth0 up
user@S:~# /sbin/ip link set eth1 up
user@S:~# 
user@S:~# /sbin/ip address add 192.0.2.1/24 dev eth0
user@S:~# /sbin/ip address add 198.51.100.1/24 dev eth1
user@S:~# 
user@S:~# /sbin/sysctl -w net.ipv4.conf.all.forwarding=1
{% endhighlight %}

### Leaf nodes

Again, when an IPv6 node wants to talk to an IPv4 one, it will append the 64::/96 prefix to the real IPv4 address. This means that the entire IPv4 universe can be seen as just a network named 64::/96.

So, just issue this on C and D:

{% highlight bash %}
user@C:~# /sbin/ip link set eth0 up
user@C:~# /sbin/ip -6 address add 2001:db8:2::10/64 dev eth0 # or ::11.
user@C:~# /sbin/ip -6 route add 2001:db8:1::/64 via 2001:db8:2::1 dev eth0
user@C:~# /sbin/ip -6 route add 64::/96 via 2001:db8:2::2 dev eth0
{% endhighlight %}

A and B are even easier; they only have one gateway, and they don't see the NAT64, so they don't even need to know it exists.

{% highlight bash %}
user@A:~# /sbin/ip link set eth0 up
user@A:~# /sbin/ip -6 address add 2001:db8:1::10/64 dev eth0 # or ::11.
user@A:~# /sbin/ip -6 route add default via 2001:db8:1::1 dev eth0
{% endhighlight %}

(The whole point of me bothering with this network is to show that you can also have IPv6 nodes completely unaware of the NAT64's existence.)

Yet again, Jool masks the IPv6 internet so IPv4 nodes cannot start conversations with IPv6 nodes; they can only respond. To them, J is just another node:

{% highlight bash %}
user@E:~# # E and F.
user@E:~# /sbin/ip link set eth0 up
user@E:~# /sbin/ip address add 192.0.2.10/24 dev eth0 # or .11.
user@E:~# /sbin/ip route add 198.51.100.0/24 via 192.0.2.1 dev eth0
{% endhighlight %}

{% highlight bash %}
user@G:~# # G and H.
user@G:~# /sbin/ip link set eth0 up
user@G:~# /sbin/ip address add 198.51.100.10/24 dev eth0 # or .11.
user@G:~# /sbin/ip route add 192.0.2.0/24 via 198.51.100.1 dev eth0
{% endhighlight %}

### NAT64

{% highlight bash %}
user@J:~# /sbin/ip link set eth0 up
user@J:~# /sbin/ip link set eth1 up
user@J:~# 
user@J:~# /sbin/ip -6 address add 2001:db8:2::2/64 dev eth0
user@J:~# /sbin/ip address add 192.0.2.2/24 dev eth1
user@J:~# /sbin/ip address add 192.0.2.3/24 dev eth1
user@J:~# 
user@J:~# /sbin/ip -6 route add 2001:db8:1::/64 via 2001:db8:2::1 dev eth0
user@J:~# /sbin/ip route add default via 192.0.2.1 dev eth1
user@J:~# 
user@J:~# /sbin/sysctl -w net.ipv4.conf.all.forwarding=1
user@J:~# /sbin/sysctl -w net.ipv6.conf.all.forwarding=1
{% endhighlight %}

There's a contrast between J's addresses (configured above) and Jool's "pool of addresses" (a subset of them). J uses its dedicated addresses to chat other nodes, and Jool uses its addresses to know which packets should be translated.

* 2001:db8:2::2 is J's address in the 2001:db8:2::/64 network. For the most part, there is nothing unusual about this: J itself (not the NAT64 mechanism) uses it to communicate with other IPv6 nodes. Again: Jool never touches this address.
* 192.0.2.2 is J's address in the 192.0.2.0/24 network. Just like 2001:db8:2::2, Jool never touches it.
* At the moment, 192.0.2.3 is also one of J's addresses in its IPv4 network, but later we'll hand it to Jool so it can tell which packets are meant to be translated and which are meant for J. Jool wants to hog it up and use it as source address for all outgoing traffic originated from the IPv6 side. Though it is _only_ used by Jool, we have to `ip addr add` it so Linux answers ARP requests for it.
* 64::/96 will be Jool's IPv6 pool of addresses. It belongs to Jool, and J can be otherwise unaware of it. Linux doesn't have to ARP reply it because the 2001:db8:2::/64 nodes already know to forward prefixed packets to 2001:db8:2::2's machine (see the routing commands in previous sections).

> **Warning!**
> 
> Sorry. In previous versions of this documentation, we used to combine J and Jool's IPv4 addresses. This has proven to be very troublesome, thus we don't recommend it anymore.
> 
> That is, if you choose to let Jool monopolize all of J's addresses, you're not going to die, but keep in mind that the NAT64 service will work for everyone except for J itself. *J will ironically be the only node unable to access IPv4 content*.

By default, Jool uses addresses 192.168.2.1 through 192.168.2.4 as its IPv4 pool, and prefix 64:ff9b::/96 as its IPv6 pool. Here's some info on them for you to chew:

* 64:ff9b::/96 has been reserved by <a href="http://tools.ietf.org/html/rfc6052#section-2.1" target="_blank">RFC 6052</a> for 6/4 translation. This prefix is not globally routable, thus you can use it as long as you're not planning to open your NAT64 service to the public.
* 192.168.2.1-4 is a consequence of our lab testing and is a dumb default we should probably remove. You always want to change it.

You override the default values while inserting the module:

{% highlight bash %}
user@J:~# # remember to turn offloads off and log martians.
user@J:~# /sbin/modprobe jool pool6=64::/96 pool4=192.0.2.3
{% endhighlight %}

We have chosen 192.0.2.2 as J's address, and 192.0.2.3 as Jool's address. You always want to `ip addr add` the module's addresses *after* the node's addresses, because if they have the same priority, the node always chooses the first available one to source its own traffic.

And booya:

{% highlight bash %}
user@C:~$ ping6 64::192.0.2.10
PING 64::192.0.2.10(64::c000:20a) 56 data bytes
64 bytes from 64::c000:20a: icmp_seq=1 ttl=63 time=0.989 ms
64 bytes from 64::c000:20a: icmp_seq=2 ttl=63 time=0.668 ms
64 bytes from 64::c000:20a: icmp_seq=3 ttl=63 time=0.603 ms
64 bytes from 64::c000:20a: icmp_seq=4 ttl=63 time=0.702 ms
^C
--- 64::192.0.2.10 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 2999ms
rtt min/avg/max/mdev = 0.603/0.740/0.989/0.150 ms
{% endhighlight %}

{% highlight bash %}
user@A:~$ ping6 64::198.51.100.10
PING 64::198.51.100.10(64::c633:640a) 56 data bytes
64 bytes from 64::c633:640a: icmp_seq=1 ttl=61 time=1.76 ms
64 bytes from 64::c633:640a: icmp_seq=2 ttl=61 time=1.27 ms
64 bytes from 64::c633:640a: icmp_seq=3 ttl=61 time=1.53 ms
64 bytes from 64::c633:640a: icmp_seq=4 ttl=61 time=1.52 ms
^C
--- 64::198.51.100.10 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 1.278/1.523/1.760/0.174 ms
{% endhighlight %}

I hope by now you can tell how you want your traffic to flow and how you can inject a stateful NAT64 gateway to any network.

You might also have noticed and be stumped by some of stateful NAT64's limitations. Here's a word on them:

1. If you didn't follow the link to [Static Bindings](static-bindings.html), you might be baffled at the fact that we haven't yet issued a single ping from a IPv4 node. Truth be told, stateful NAT64 is formally defined as "Address and Protocol Translation from IPv6 Clients to IPv4 Servers", which means that IPv6 nodes starting communications is an assumption that happily takes over a big chunk of the RFC. IPv4 clients accesing a _limited_ amount of IPv6 servers is possible though, follow the link to find the details.
2. Also, scenario 3 hides any number of IPv6 nodes behind a single IPv4 address. How can a NAT64 potentially hide the entire IPv6 internet behind a single puny IPv4 address? Perhaps NAT64 also mangles ports, but then doesn't it mean that you're only limited to 65536 translated connections at a time?

Go to the [third tutorial](tutorial3.html) to find out about that.

