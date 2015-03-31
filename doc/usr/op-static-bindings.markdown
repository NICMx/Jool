---
layout: documentation
title: Documentation - Static Bindings
---

[Documentation](doc-index.html) > [Runs](doc-index.html#runs) > [Stateful NAT64](mod-run-stateful.html) > Static Bindings

# Static Bindings

When a translation from IPv6 to IPv4 happens, very little is left of the headers of the original packet. Because of this, Jool has to remember who tried to speak with whom and on which ports, so when answers arrive, it can figure out which conversation the packet belongs to, and mangle the headers correctly. This is not only a quirk of Stateful NAT64; traditional Stateful NAT lives it as well.

The database the bindings are stored in is called hte "[Binding Information Base](misc-bib.html)" (BIB). Each record in the database contains an IPv4 address _A_ and its port _b_, and an IPv6 address _C_ and its port _d_. The record basically says, "If a packet towards address _A_ on port _b_ arrives, translate and forward it to address _C_ on port _d_".

Why do you need to know that? A basic Stateful NAT64 installation will give your IPv6 network access to your average IPv4 Internet, but it's a little or very annoying that IPv4 nodes cannot talk to IPv6 ones without the latter having started the conversations. However, NAT64 does inherit from NAT the ability to configure manual bindings between inner and outer nodes ("<a href="http://en.wikipedia.org/wiki/Port_forwarding" target="_blank">Port forwarding</a>"). If you want to say, publish a server on your IPv6 network for the IPv4 nodes to see, then you have to hack a manual BIB entry into the database.

![Fig.1 - Network design](images/static-network.svg)

So what we have here is, the IPv6 nodes can see a HTTP server by querying 1::1 on port 80. What we want is to make it available to the outside via the 1.2.3.4 address on port 5678 (We'll use a different port simply because we can).

To create a mapping, you have to ask the [userspace application](usr-install.html) something in the lines of this:

	$ jool --bib --add <protocols> <Ipv6 address>#<"IPv6" port> <IPv4 address>#<"IPv4" port>

which in our example will translate into:

	$ jool --bib --add --tcp 1::1#80 1.2.3.4#5678

> If it throws you an error, run `dmesg` to know the cause. Most likely you're using an IPv4 address you didn't add to the pool. Add the address like this:
> 
> 	$ jool --pool4 --add 1.2.3.4
> 
> Then retry the insertion of the mapping.

And have fun.

![Fig.2 - Test](images/static-hiya.png)

Run an operationless version of the `--bib` command to display your current database:

	$ jool --bib
	TCP:
	[Static] 1.2.3.4#5678 - 1::1#80
	  (Fetched 1 entries.)
	UDP:
	  (empty)
	ICMP:
	  (empty)

If your output shows a more populated table, it's because Jool has been translating traffic. Static (manual) and dynamic (created by Jool) mappings belong to the same database.

Note that there are not one, but three different BIB tables. We added the entry only to the TCP BIB because we used the `--tcp` parameter.

	$ # Add an entry to the UDP BIB
	$ jool --bib --add --udp 1::1#80 1.2.3.4#5678
	$ # Add an entry to the UDP and ICMP BIBs
	$ jool --bib --add --udp --icmp 1::1#80 1.2.3.4#5678
	$ # Show the three tables.
	$ jool --bib --tcp --udp --icmp
	$ # Show the three BIBs, quick version.
	$ jool --bib
	$ # (We didn't include any protocols, so Jool assumed we wanted to show every table.)

"Hold on!", I hear you scream. "The ICMP protocol doesn't use ports!". But it does use ICMP identifiers, which are very similar. It doesn't really make much sense to create manual ICMP mappings, though, since ICMP identifiers are often unpredictable (as opposed to destination ports).

If you need to remove the binding, replace "add" for "remove" and specify either side of the equation (Mappings are unique on both sides):

{% highlight bash %}
$ jool --bib --remove --tcp 1::1#80
or
$ jool --bib --remove --tcp 1.2.3.4#5678
or
$ # This won't hurt you (and will make sure you're removing exactly what you want to remove).
$ jool --bib --remove --tcp 1::1#80 1.2.3.4#5678
{% endhighlight %}

