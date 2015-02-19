---
layout: documentation
title: Documentation - Flags > EAMT
---

[Documentation](doc-index.html) > [Userspace Application](doc-index.html#userspace-application) > [Flags](usr-flags.html) > \--eamt

# \--eamt

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Options](#options)
   2. [Operations](#operations)
   4. [`--csv`](#csv)
   5. [`<prefix4>`, `<prefix6>`](#prefix4-prefix6)
4. [Examples](#examples)

## Description

Interacts with Jool's Explicit Address Mapping Table (EAMT). See [the introduction](intro-nat64.html#stateless-nat64-with-eam) for a swift overview or the [EAM draft](https://tools.ietf.org/html/draft-anderson-v6ops-siit-eam-02) for the full story.

## Syntax

	jool_stateless --eamt [--display] [--csv]
	jool_stateless --eamt --count
	jool_stateless --eamt --add <prefix4> <prefix6>
	jool_stateless --eamt --remove (<prefix4> | <prefix6> | <prefix4> <prefix6>)
	jool_stateless --eamt --flush

## Options

### Operations

* `--display`: The EAMT is printed in standard output. This is the default operation.
* `--count`: The number of entries in the EAMT are printed in standard output.
* `--add`: Combines `<prefix4>` and `<prefix6>` into an EAM entry, and uploads it to Jool's table.
* `--remove`: Deletes from the table the EAM entry described by `<prefix4>` and/or `<prefix6>`.
* `--flush`: Removes all entries from the table.

### `--csv`

By default, the application will print the tables in a relatively console-friendly format.

Use `--csv` to print in <a href="http://en.wikipedia.org/wiki/Comma-separated_values" target="_blank">CSV format</a>, which is spreadsheet-friendly.

### `<prefix4>`, `<prefix6>`

	<prefix4> := <IPv4 address>[/<prefix length>]
	<prefix6> := <IPv6 address>[/<prefix length>]

An EAMT entry is composed of an IPv6 prefix and an IPv4 prefix. When an address is being translated, its prefix is literally replaced according to the table.

For example, assume the following EAMT:

| IPv4 Prefix  | IPv6 Prefix    |
|--------------|----------------|
| 192.0.2.0/24 | 2001:db8::/120 |

If an IPv4 packet arrives including address 192.0.2.8, Jool will translate it into 2001:db8::8. If an IPv6 packet arrives including address 2001:db8::d, Jool will translate it into 192.0.2.13. Notice the suffix is always preserved, so the point is a single EAMT entry can describe the translation of an entire network.

TODO describe the IVI feature?

`<prefix length>` defaults to /32 on `<prefix4>` and /128 on `<prefix6>`. Jool automatically zeroizes any suffix from either address if it exists.

Every prefix is unique accross the table. Therefore, If you're removing an EAMT entry, you actually only need to provide one of them. You can still input both to make sure you're deleting exactly what you want to delete, though.

## Examples

Add a handful of mappings:

{% highlight bash %}
# jool_stateless --eamt --add 192.0.2.1      2001:db8:aaaa::
# jool_stateless --eamt --add 192.0.2.2/32   2001:db8:bbbb::b/128
# jool_stateless --eamt --add 192.0.2.16/28  2001:db8:cccc::/124
# jool_stateless --eamt --add 192.0.2.128/26 2001:db8:dddd::/64
# jool_stateless --eamt --add 192.0.2.192/31 64:ff9b::/127
{% endhighlight %}

Display the new table:

{% highlight bash %}
$ jool_stateless --eamt --display
64:ff9b::/127 - 192.0.2.192/31
2001:db8:dddd::/64 - 192.0.2.128/26
2001:db8:cccc::/124 - 192.0.2.16/28
2001:db8:bbbb::b/128 - 192.0.2.2/32
2001:db8:aaaa::/128 - 192.0.2.1/32
  (Fetched 5 entries.)
{% endhighlight %}

Dump the database on a CSV file:

{% highlight bash %}
$ jool_stateless --eamt --display --csv > eamt.csv
{% endhighlight %}

[eamt.csv](obj/eamt.csv)

Display the number of entries in the table:

{% highlight bash %}
$ jool_stateless --eamt --count
5
{% endhighlight %}

Remove the first entry:

{% highlight bash %}
# jool_stateless --eamt --remove 2001:db8:aaaa::
{% endhighlight %}

Empty the table:

{% highlight bash %}
# jool_stateless --eamt --flush
{% endhighlight %}

