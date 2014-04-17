---
layout: documentation
title: Documentation - Static Bindings
---

# Static Bindings

When a translation from IPv6 to IPv4 happens, very little is left of the headers of the original packet. Because of this, Jool has to remember who tried to speak with whom and on which ports, so when answers arrive, it can figure out which conversation the packet belongs to, and mangle the headers correctly. This is not a quirk of NAT64; traditional NAT lives it as well.

The database the bindings are stored in is called "Binding Information Base" (BIB). Each record in the database contains an IPv4 address _A_ and its port _b_, and an IPv6 address _C_ and its port _d_. The record basically says, "If a packet towards address _A_ on port _b_ arrives, translate and forward it to address _C_ on port _d_".

Why do you need to know that? A basic NAT64 installation will give your IPv6 network access to your average IPv4 Internet, but it's a little or very annoying that IPv4 nodes cannot talk to IPv6 ones without the latter having started the conversations. However, NAT64 does inherit from NAT the ability to configure manual bindings between inner and outer nodes. If you want to say, publish a server on your IPv6 network for the IPv4 nodes to see, then you have to hack a manual BIB entry into the database.

![Fig.1 - Network design](images/static-network.svg)

So what we have here is, the IPv6 nodes can see a HTTP server by querying 1::1 on port 80. What we want is to make it available to the outside via the 1.2.3.4 address on port 5678 (We'll use a different port just because we can).

You cannot tell the NAT64 the static bindings during module insertion because that'd be very cumbersome, so we devised a [userspace client](userspace-app.html) for you to talk to Jool with. Install following the steps outlined [here](userspace-app.html#introduction).

Now to actually create the mapping, you have to run something in the lines of this:

{% highlight bash %}
$ jool --bib --add <protocols> --bib6=<Ipv6 address>#<"IPv6" port> --bib4=<IPv4 address>#<"IPv4" port>
{% endhighlight %}

which in our example will translate into:

{% highlight bash %}
$ jool --bib --add --tcp --bib6=1::1#80 --bib4=1.2.3.4#5678
{% endhighlight %}

> If it throws you an error, run `dmesg` to know the cause. Most likely you're using an IPv4 address you didn't add to the pool. You can remove the module and re-insert it using the correct parameter, but since you now know the userspace application you can just type
> 
> 	$ jool --pool4 --add --address=1.2.3.4
> 
> Then retry the insertion of the mapping.

And have fun.

![Fig.2 - Test](images/static-hiya.png)

Yes, the command is a little redundant. You can abbreviate it if you want:

{% highlight bash %}
$ jool -bat --bib6=1::1#80 --bib4=1.2.3.4#5678
{% endhighlight %}

Run an operationless version of the `--bib` command to display your current database:

{% highlight bash %}
$ jool --bib
TCP:
[Static] 1.2.3.4#5678 - 1::1#80
  (Fetched 1 entries.)
UDP:
  (empty)
ICMP:
  (empty)
{% endhighlight %}

If your output shows a more populated table, it's because Jool has been translating traffic. Static (manual) and dynamic (created by Jool) mappings belong to the same database.

Note that there are not one, but three different BIBs. We added the entry only to the TCP BIB because we used the `--tcp` parameter.

{% highlight bash %}
$ # Add an entry to the UDP BIB
$ jool --bib --add --udp --bib6=... --bib4=...
$ # Add an entry to the TCP and ICMP BIBs
$ jool --bib --add --udp --icmp --bib6=... --bib4=...
$ # Show the three tables.
$ jool --bib --tcp --udp --icmp
$ # Show the three BIBs, quick version.
$ jool --bib -tui
$ # Add an entry to the three BIBs, quicker version.
$ jool -batui --bib6=... --bib4=...
{% endhighlight %}

"Hold on!", I hear you scream. "The ICMP protocol doesn't use ports!". But it does use ICMP identifiers, which are very similar. It doesn't really make much sense to create manual ICMP mappings, though, since ICMP identifiers are often unpredictable (as opposed to destination ports).

If you need to remove the binding, replace "add" for "remove" and specify either side of the equation (Mappings are unique on both sides):

{% highlight bash %}
$ jool --bib --remove --tcp --bib6=1::1#80
or
$ jool --bib --remove --tcp --bib4=1.2.3.4#5678
or
$ jool -brt --bib6=1::1#80
or
$ jool -brt --bib4=1.2.3.4#5678
{% endhighlight %}

[Click here](userspace-app.html) for more on what the application can be used for.

