---
language: en
layout: default
category: Documentation
title: session Mode
---

[Documentation](documentation.html) > [Userspace Clients](documentation.html#userspace-clients) > `session` Mode

# `session` Mode

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Subcommands](#subcommands)
   1. [display](#display)
   2. [follow](#follow)
   3. [proxy](#proxy)
   4. [advertise](#advertise)
4. [Examples](#examples)

## Description

From Jool's point of view, sessions mostly exist so the NAT64 can decide when BIB entries should die. You can also use them to know exactly who is speaking to your IPv6 nodes.

Each BIB entry is a mapping, which describes the IPv4 name of one of your IPv6 services. For every BIB entry, there are zero or more session entries, each of which represents an active connection currently using that mapping.

You can use this command to get information on each of these connections.

## Syntax

	jool [-i INAME] session (
		display [--tcp | --udp | --icmp]
			[--numeric]
			[--csv]
			[--no-headers]
		| follow
		| proxy [--net.mcast.port=STR]
			[--net.dev.in=STR]
			[--net.dev.out=STR]
			[--net.ttl]
			[--stats.address=STR]
			[--stats.port=STR]
			NET_MCAST_ADDR
		| advertise
	)

## Subcommands

### display

The session table that corresponds to the `PROTOCOL` protocol is printed in standard output.

| **Flag** | **Description** |
| `--tcp` | Operate on the TCP table. This is the default protocol. |
| `--udp` | Operate on the UDP table. |
| `--icmp` | Operate on the ICMP table. |
| `--numeric` | By default, `display` will attempt to resolve the names of the remote nodes involved in each session. _If your nameservers aren't answering, this will pepper standard error with messages and slow the output down_.<br />Use `--numeric` to disable the lookups. |
| `--csv` | Print the table in [_Comma/Character-Separated Values_ format](http://en.wikipedia.org/wiki/Comma-separated_values). This is intended to be redirected into a .csv file.<br />Because every record is printed in a single line, CSV is also better for grepping. |
| `--no-headers` | Print the table entries only; omit the headers. (Table headers exist only on CSV mode.) |

### follow

Listen to `INAME`'s sessions (whenever they are updated) forever, printing them in standard output.

The `INAME` instance must have [SS](usr-flags-global.html#ss-enabled) enabled:

```bash
$ jool -i "default" global update ss-enabled true
$ jool -i "default" session follow
TCP,2001:db8::8,37878,192.0.2.1,62805,192.0.2.8,1234,0:04:00
TCP,2001:db8::8,37878,192.0.2.1,62805,192.0.2.8,1234,1:59:58.232
UDP,2001:db8::8,60927,192.0.2.1,62806,192.0.2.8,1234,0:04:59.028
UDP,2001:db8::8,60927,192.0.2.1,62806,192.0.2.8,1234,0:04:59.292
ICMP,2001:db8::8,211,192.0.2.1,15308,192.0.2.8,15308,0:01:00
ICMP,2001:db8::8,211,192.0.2.1,15308,192.0.2.8,15308,0:00:57.512
```

It's a bit different from [`logging-session`](usr-flags-global.html#logging-session) in that it doesn't print the sessions' death.

For TCP and UDP, the columns are

- IPv6 peer address
- IPv6 peer port
- IPv4-masked IPv6 peer address
- IPv4-masked IPv6 peer port
- IPv4 peer address
- IPv4 peer port
- Layer 4 Protocol (pretends ICMP is L4)
- Milliseconds to expiration

Please note that the IPv6-masked IPv4 peer address is excluded because it always equals [pool6](usr-flags-global.html#pool6) plus the IPv4 peer address. The IPv6-masked IPv4 peer port is also excluded, because it always equals the IPv4 peer port.

For ICMP,

- IPv6 peer address
- IPv6 ICMP identifier
- IPv4-masked IPv6 peer address
- IPv4 identifier
- IPv4 peer address
- IPv4 identifier (yes, this is redundant)
- Layer 4 Protocol (pretends ICMP is L4)
- Milliseconds to expiration

### proxy

Listen to sessions forever, exchanging them between the `INAME` instance and other listening proxies. A tutorial can be found [here](session-synchronization.html).

> Until Jool 4.1.12, the session proxy used to be named "joold". As a matter of fact, the `joold` binary still exists, but it's deprecated.

The `INAME` instance must have [SS](usr-flags-global.html#ss-enabled) enabled.

#### `NET_MCAST_ADDR`

- Type: String (IPv4/v6 address)
- Default: None (Mandatory)

Address the SS traffic will be sent to and listened from.

#### `--net.mcast.port`

- Type: String (port number or service name)
- Default: 6400

UDP port where the SS traffic will be sent to and listened from.

#### `--net.dev.in`

- Type: String
- Default: NULL (kernel chooses interface and address for you)

Address or interface to bind the socket in.

If `NET_MCAST_ADDR` is IPv4, this should be one addresses from the interface where the SS traffic is expected to be received. If `NET_MCAST_ADDR` is IPv6, this should be the name of the interface (eg. "eth0").

Though they are optional, it is recommended that you define both `--net.dev.in` and `--net.dev.out` to ensure the SS traffic does not leak through other interfaces.

#### `--net.dev.out`

- Type: String
- Default: NULL (kernel chooses interface and address for you)

If `NET_MCAST_ADDR` is IPv4, this should be one addresses from the interface where the multicast traffic is expected to be sent. If `NET_MCAST_ADDR` is IPv6, this should be the name of the interface (eg. "eth0").

Though they are optional, it is strongly recommended that you define both `--net.dev.in` and `--net.dev.out` to ensure the SS traffic does not leak through other interfaces.

#### `--net.ttl`

- Type: Integer
- Default: 1

Same as `IP_MULTICAST_TTL`. From `man 7 ip`:

	IP_MULTICAST_TTL (since Linux 1.2)
		Set or read the time-to-live value of outgoing multicast packets
		for this socket. It is very important for multicast packets to
		set the smallest TTL possible. The default is 1 which means that
		multicast packets don't leave the local network unless the user
		program explicitly requests it. Argument is an integer.

#### `--stats.address`

- Type: String (IPv4/v6 address)
- Default: "::"

Address for statistics server. It's optional; if you don't configure `--stats.address` and/or `--stats.port`, `jool session proxy` will not start the server.

It's presently rudimentary, as it was spawned by a debugging session. Sample query:

```bash
$ echo "" | nc -u 127.0.0.1 45678
KERNEL_SENT_PKTS,4
KERNEL_SENT_BYTES,208
NET_RCVD_PKTS,0
NET_RCVD_BYTES,0
NET_SENT_PKTS,4
NET_SENT_BYTES,208
```

- `KERNEL_SENT_PKTS`: Packets sent to the kernel module. (It should match the local instance's `JSTAT_JOOLD_PKT_RCVD` stat.)
- `KERNEL_SENT_BYTES`: Session bytes sent to the kernel module. (It should match the local instance's `JSTAT_JOOLD_SSS_RCVD` multiplied by the session size.)
- `NET_RCVD_PKTS`: Packets received from the network. (It should match the remote instance's `JSTAT_JOOLD_PKT_SENT`.)
- `NET_RCVD_BYTES`: Session bytes received from the network. (It should match the remote instance's `JSTAT_JOOLD_SSS_SENT` multiplied by the session size.)
- `NET_SENT_PKTS`: Packets sent to the network. (It should match the remote `jool`'s `NET_RCVD_PKTS`.)
- `NET_SENT_BYTES`: Session bytes sent to the network. (It should match the remote `jool`'s `NET_RCVD_BYTES`.)

Note, because of Linux quirks, `--stats.address=0.0.0.0` does not imply `::`, but `--stats.address=::` implies `0.0.0.0`. If you want the stats served via IPv6 but not IPv4, probably block them by firewall.

#### `--stats.port`

- Type: String (port number or service name)
- Default: 6401

Port for the [`--stats.address`](#--statsaddress) server.

### advertise

Commands the module to multicast the entire session database. This can be useful if you've recently added a new NAT64 to a [session sync](#session-synchronization) cluster.

_The size of the session database can make this is an expensive operation_; executing this command repeatedly is not recommended.

Only one Jool instance needs to advertise when a new NAT64 joins the group; the databases are supposed to be identical.

This exists because the synchronization protocol, at least in this first iteration, is very minimalistic. The instances only announce their sessions to everyone else; there are no handshakes or agreements. Full advertisements need to be triggered manually.

## Examples

![Fig.1 - Session sample network](../images/usr-session.svg)

`ipv6client.mx` makes two HTTP requests and a ping to `example.com`.

Show the TCP table, resolve names, console format:

{% highlight bash %}
user@T:~# jool session display
---------------------------------
(V4_FIN_V6_FIN_RCV) Expires in 2 minutes, 57 seconds
Remote: example.com#http	ipv6client.mx#58239
Local: 192.0.2.1#60477		64:ff9b::5db8:d877#80
---------------------------------
(V4_FIN_V6_FIN_RCV) Expires in 3 minutes, 52 seconds
Remote: example.com#http	ipv6client.mx#58237
Local: 192.0.2.1#6617		64:ff9b::5db8:d877#80
---------------------------------
{% endhighlight %}

Show the TCP table, do not query the DNS, console format:

{% highlight bash %}
user@T:~# jool session display --tcp --numeric
---------------------------------
(V4_FIN_V6_FIN_RCV) Expires in 2 minutes, 57 seconds
Remote: 93.184.216.119#80	2001:db8::2#58239
Local: 192.0.2.1#60477		64:ff9b::5db8:d877#80
---------------------------------
(V4_FIN_V6_FIN_RCV) Expires in 3 minutes, 52 seconds
Remote: 93.184.216.119#80	2001:db8::2#58237
Local: 192.0.2.1#6617		64:ff9b::5db8:d877#80
---------------------------------
{% endhighlight %}

Do not resolve names, CSV format:

{% highlight bash %}
user@T:~# jool session display --numeric --csv > session.csv
{% endhighlight %}

[session.csv](../obj/session.csv)
