---
layout: documentation
title: Documentation - Userspace Application
---

# [Doc](doc-index.html) > [Userspace App](doc-index.html#userspace-application) > [Flags](usr-flags.html) > \--bib

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Options](#options)
   1. [&lt;protocols&gt;](#ltprotocolsgt)
   2. [Operations](#operations)
   3. [\--numeric](#numeric)
   4. [\--csv](#csv)
   5. [\--bib4, \--bib6](#bib4---bib6)
4. [Examples](#examples)

## Description

Interacts with Jool's [Binding Information Base (BIB)](misc-bib.html). If you don't know what that is, please follow the link before continuing.

## Syntax

	jool_stateful --bib <protocols> [--display] [--numeric] [--csv]
	jool_stateful --bib <protocols> --count
	jool_stateful --bib <protocols> --add --bib4 <bib4> --bib6 <bib6>
	jool_stateful --bib <protocols> --remove --bib4 <bib4> --bib6 <bib6>

## Options

### &lt;protocols&gt;

	<protocols> := [--tcp] [--udp] [--icmp]

The command will only operate on the tables mentioned here. If you omit this entirely, Jool will fall back to operate on all three tables.

### Operations

* `--display`: The BIB tables are printed in standard output. This is the default operation.
* `--count`: The number of entries per BIB table are printed in standard output.
* `--add`: Combines `--bib6` and `--bib4` into a BIB entry, and uploads it to Jool's tables.
* `--remove`: Deletes from the tables the BIB entry described by `--bib6` and/or `--bib4`.

### \--numeric

By default, the application will attempt to resolve the name of the IPv6 node of each BIB entry. _If your nameservers aren't answering, this will slow the output down_.

Use `--numeric` to turn this behavior off.

### \--csv

By default, the application will print the tables in a relatively console-friendly format.

Use `--csv` to print in <a href="http://en.wikipedia.org/wiki/Comma-separated_values" target="_blank">CSV format</a>, which is spreadsheet-friendly.

### \--bib4, \--bib6

	<bib4> := <IPv4 address>#(<port> | <ICMP identifier>)
	<bib6> := <IPv6 address>#(<port> | <ICMP identifier>)

A BIB entry is composed of a IPv6 transport address (the IPv6 node's connection identifiers) and a IPv4 transport address (the connection identifiers Jool is using to mask the IPv6 ones).

If you're adding or removing a BIB, you provide both addresses via these parameters.

Note that the `--bib4` component must be a member of Jool's [IPv4 pool](usr-flags-pool4.html), so make sure you have registered it there first.

Within a BIB table, every IPv4 transport address is unique. Within a BIB table, every IPv6 transport address is also unique. Therefore, If you're removing a BIB entry, you actually only need to provide one of them. You can still input both to make sure you're deleting exactly what you want to delete, though.

## Examples

Assumptions:

* 4.4.4.4 belongs to the IPv4 pool.
* The name of 6::6 is "potato.mx".
* 6::6 already spoke to a IPv4 node recently, so the database will not start empty.

Display the entire database:

{% highlight bash %}
$ jool_stateful --bib --display
TCP:
[Dynamic] 4.4.4.4#1234 - potato.mx#1234
  (Fetched 1 entries.)
UDP:
  (empty)
ICMP:
  (empty)
{% endhighlight %}

Publish a couple of TCP services:

{% highlight bash %}
# jool_stateful --bib --add --tcp --bib6 6::6#6 --bib4 4.4.4.4#4
# jool_stateful --bib --add --tcp --bib6 6::6#66 --bib4 4.4.4.4#44
{% endhighlight %}

Display the TCP table:

{% highlight bash %}
$ jool_stateful --bib --display --tcp
TCP:
[Static] 4.4.4.4#4 - potato.mx#6
[Static] 4.4.4.4#44 - potato.mx#66
[Dynamic] 4.4.4.4#1234 - potato.mx#1234
  (Fetched 3 entries.)
{% endhighlight %}

Same, but do not query the DNS:

{% highlight bash %}
$ jool_stateful --bib --display --tcp --numeric
TCP:
[Static] 4.4.4.4#4 - 6::6#6
[Static] 4.4.4.4#44 - 6::6#66
[Dynamic] 4.4.4.4#1234 - 6::6#1234
  (Fetched 3 entries.)
{% endhighlight %}

Publish a UDP service:

{% highlight bash %}
# jool_stateful --bib --add --udp --bib6 6::6#6666 --bib4 4.4.4.4#4444
{% endhighlight %}

Dump the database on a CSV file:

{% highlight bash %}
$ jool --bib --display --numeric --csv > bib.csv
{% endhighlight %}

[bib.csv](obj/bib.csv)

Display the number of entries in the TCP and ICMP tables:

{% highlight bash %}
$ jool_stateful --bib --count --tcp --icmp
TCP: 3
ICMP: 0
{% endhighlight %}

Remove the UDP entry:

{% highlight bash %}
# jool_stateful --bib --remove --udp --bib6 6::6#6666
{% endhighlight %}

