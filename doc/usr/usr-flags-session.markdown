---
layout: documentation
title: Documentation - Userspace Application
---

# Userspace Application > Flags > \--session

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Options](#options)
   1. [Operations](#operations)
   2. [&lt;protocols&gt;](#ltprotocolsgt)
   3. [\--numeric](#numeric)
   4. [\--csv](#csv)
4. [Examples](#examples)

[Back to Flags](usr-flags.html).

## Description

Sessions mostly exist so the NAT64 can decide when BIB entries should die. You can also use them to know exactly who is speaking to your IPv6 nodes. In a future release you will also be able to <a href="https://github.com/NICMx/NAT64/issues/41" target="_blank">define filtering policies based on them</a>.

Each BIB entry is a mapping, which describes the IPv4 name of one of your IPv6 services. For every BIB entry, there are zero or more session entries, each of which represents an active connection currently using that mapping.

You can use this command to get information on each of these connections.

## Syntax

	jool --session [--display] [--numeric] [--csv] <protocols>
	jool --session --count <protocols>

## Options

### Operations

* `--display`: The session tables are printed in standard output. This is the default operation.
* `--count`: The number of entries per session table are printed in standard output.

### &lt;protocols&gt;

	<protocols> := [--tcp] [--udp] [--icmp]

The command will only operate on the tables mentioned here. If you omit this entirely, Jool will fall back to operate on all three tables.

### \--numeric

By default, the application will attempt to resolve the names of the remote nodes talking in each session. _If your nameservers aren't answering, this will slow the output down_.

Use `--numeric` to turn this behavior off.

### \--csv

By default, the application will print the tables in a relatively console-friendly format.

Use `--csv` to print in <a href="http://en.wikipedia.org/wiki/Comma-separated_values" target="_blank">CSV format</a>, which is spreadsheet-friendly.

Because every record is printed in a single line, CSV is also better for grepping.

## Examples

![Fig.1 - Session sample network](images/usr-session.svg)

ipv6client.mx makes two HTTP requests and a ping to example.com.

Fall back to display all protocols, resolve names, console format:

{% highlight bash %}
$ jool --session
TCP:
---------------------------------
(V4_FIN_V6_FIN_RCV) Expires in 2 minutes, 57 seconds
Remote: example.com#http	ipv6client.mx#58239
Local: 192.0.2.1#60477		64:ff9b::5db8:d877#80
---------------------------------
(V4_FIN_V6_FIN_RCV) Expires in 3 minutes, 52 seconds
Remote: example.com#http	ipv6client.mx#58237
Local: 192.0.2.1#6617		64:ff9b::5db8:d877#80
---------------------------------
  (Fetched 2 entries.)

UDP:
---------------------------------
  (empty)

ICMP:
---------------------------------
Expires in 50 seconds
Remote: example.com#1402	ipv6client.mx#13371
Local: 192.0.2.1#1402		64:ff9b::5db8:d877#13371
---------------------------------
  (Fetched 1 entries.)
{% endhighlight %}

Filter out UDP and ICMP, do not query the DNS, console format:

{% highlight bash %}
$ jool --session --display --tcp --numeric
TCP:
---------------------------------
(V4_FIN_V6_FIN_RCV) Expires in 2 minutes, 57 seconds
Remote: 93.184.216.119#80	2001:db8::2#58239
Local: 192.0.2.1#60477		64:ff9b::5db8:d877#80
---------------------------------
(V4_FIN_V6_FIN_RCV) Expires in 3 minutes, 52 seconds
Remote: 93.184.216.119#80	2001:db8::2#58237
Local: 192.0.2.1#6617		64:ff9b::5db8:d877#80
---------------------------------
  (Fetched 2 entries.)
{% endhighlight %}

Do not resolve names, CSV format:

{% highlight bash %}
$ jool --session --display --numeric --csv > session.csv
{% endhighlight %}

[session.csv](obj/session.csv)

Just display the number of records of every table:

{% highlight bash %}
$ jool --session --count
TCP: 2
UDP: 0
ICMP: 1
{% endhighlight %}

