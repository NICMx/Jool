---
language: en
layout: default
category: Documentation
title: Userspace Clients General Usage
---

[Documentation](documentation.html) > [Userspace Clients](documentation.html#userspace-clients) > General usage

# Userspace Clients General Usage

## Index

1. [Syntax](#syntax)
2. [Arguments](#arguments)
3. [Quirks](#quirks)

## Syntax

All userspace client command line requests adhere to the following syntax:

	(jool_siit | jool) [-i <instance-name>] <mode> <operation> [<args>]

## Arguments

`jool` and `jool_siit` are the names of the two available userspace client binaries. The `jool` client speaks to the `jool` kernel module, and the `jool_siit` client speaks to the `jool_siit` kernel module.

`<instance name>` is the name of the instance (defined in [`instance add`](usr-flag-instance.html)) you want to interact with. It defaults to "`default`."

`<mode>` is (usually) one of the following keywords:

- [`instance`](usr-flags-instance.html)
- [`stats`](usr-flags-stats.html)
- [`global`](usr-flags-global.html)
- [`eamt`](usr-flags-eamt.html) (SIIT only)
- [`blacklist4`](usr-flags-blacklist4.html) (SIIT only)
- [`pool4`](usr-flags-pool4.html) (NAT64 only)
- [`bib`](usr-flags-bib.html) (NAT64 only)
- [`session`](usr-flags-session.html) (NAT64 only)

`<operation>` is (usually) one of the following keywords:

- `display`
- `add`
- `update`
- `remove`
- `flush`

And finally, `<args>` is an traditional argp-parsed payload of arguments that depend on the `<mode> <operation>` context. For example, list the `instance add` flags by running

{% highlight bash %}
user@T:~$ jool instance add --help
{% endhighlight %}

The only exception is [`global update`](usr-flags-global.html), where the value key acts as a third keyword level:

{% highlight bash %}
user@T:~$ jool global update <key> --help
{% endhighlight %}

## Quirks

As long as you don't reach ambiguity, you can abbreviate keywords:

{% highlight bash %}
user@T:~# jool_siit i a    # instance add
user@T:~# jool      g u    # global update
user@T:~# jool_siit s d    # stats display
user@T:~# jool      s d    # Error: stats or session? display
{% endhighlight %}

Of course, do not rely on these shorthands during scripts. There is no guarantee that future new keywords will not induce ambiguity.
