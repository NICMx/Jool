---
language: en
layout: default
category: Documentation
title: Daemon Configuration Options
---

[Documentation](documentation.html) > [Other Configuration](documentation.html#other-configuration) > Daemon Configuration Options

# Daemon Configuration Options

## Index

1. [Introduction](#introduction)
2. [Kernel Socket Configuration](#kernel-socket-configuration)
3. [Network Socket Configuration](#network-socket-configuration)
4. [Statistics Socket Configuration](#statistics-socket-configuration)

## Introduction

`joold` (Jool's userspace daemon binary) is part of the [Session Synchronization](session-synchronization.html) gimmic. Follow the link for context.

Syntax:

```
joold
      --version               # Print program version number
    | --help                  # Print argument reminders
    | (
                              # Kernel Socket Configuration
      [--mod=FILE]            # Path to file containing kernel socket config
      [--instance=STR]        # Kernelspace Jool instance name (Default: "default")

                              # Network Socket Configuration
      [--net=FILE]            # Path to file containing --net.* arguments
      [--net.mcast.addr=ADDR] # Address where the sessions will be advertised
      [--net.mcast.port=STR]  # UDP port where the sessions will be advertised
      [--net.dev.in=STR]      # IPv4: IP_ADD_MEMBERSHIP; IPv6: IPV6_ADD_MEMBERSHIP (see ip(7))
      [--net.dev.out=STR]     # IPv4: IP_MULTICAST_IF, IPv6: IPV6_MULTICAST_IF (see ip(7))
      [--net.ttl=INT]         # Multicast datagram Time To Live

                              # Statistics Socket Configuration
      [--stats=FILE]          # Path to file containing --stats.* arguments
      [--stats.addr=ADDR]     # Address to bind the stats socket to
      [--stats.port=INT]      # Port to bind the stats socket to
    )
```

## Kernel Socket Configuration

This configures the daemon's Netlink socket; the one it uses to communicate with its designated kernelspace Jool instance.

It only has one option: The name of the kernelspace Jool instance you designated during [`jool instance add`](usr-flags-instance.html). As usual, it defaults to "`default`."

Send it as a program argument:

```bash
$ joold --instance potato
```

Or feed it from a file:

```bash
$ cat modsocket.json
{ "instance": "potato" }
$ joold --mod modsocket.json
```

The kernel instance needs to be located in the same network namespace as its daemon.

## Network Socket Configuration

This configures the daemon's network socket; the one it uses to communicate with other synchronization daemons.

Sample configuration file:

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">IPv6</span>
	<span class="distro-selector" onclick="showDistro(this);">IPv4</span>
</div>

<!-- IPv6 -->
```json
{
	"multicast address": "ff08::db8:64:64",
	"multicast port": "6464",
	"in interface": "eth0",
	"out interface": "eth0",
	"ttl": 3
}
```

<!-- IPv4 -->
```json
{
	"multicast address": "233.252.0.64",
	"multicast port": "6464",
	"in interface": "192.0.2.1",
	"out interface": "192.0.2.1",
	"ttl": 3
}
```

These are the options:

### `multicast address` (`--net.mcast.addr`)

- Type: String (IPv4/v6 address)
- Default: None (The network socket is disabled if absent)

Address the SS traffic will be sent to and listened from.

### `multicast port` (`--net.mcast.port`)

- Type: String (port number or service name)
- Default: None (The network socket is disabled if absent)

TCP port where the SS traffic will be sent to and listened from.

### `in interface` (`--net.dev.in`)

- Type: String
- Default: NULL (kernel chooses an interface and address for you)

Address or interface to bind the socket in.

If `multicast address` is IPv4, this should be one addresses from the interface where the SS traffic is expected to be received. If `multicast address` is IPv6, this should be the name of the interface (eg. "eth0").

Though they are optional, it is strongly recommended that you define both `in interface` and `out interface` to ensure the SS traffic does not leak through other interfaces.

### `out interface` (`--net.dev.out`)

- Type: String
- Default: NULL (kernel chooses an interface and address for you)

If `multicast address` is IPv4, this should be one addresses from the interface where the multicast traffic is expected to be sent. If `multicast address` is IPv6, this should be the name of the interface (eg. "eth0").

Though they are optional, it is strongly recommended that you define both `in interface` and `out interface` to ensure the SS traffic does not leak through other interfaces.

### `ttl` (`--net.ttl`)

- Type: Integer
- Default: 1

Same as `IP_MULTICAST_TTL`. From `man 7 ip`:

	IP_MULTICAST_TTL (since Linux 1.2)
		Set or read the time-to-live value of outgoing multicast packets
		for this socket. It is very important for multicast packets to
		set the smallest TTL possible. The default is 1 which means that
		multicast packets don't leave the local network unless the user
		program explicitly requests it. Argument is an integer.

## Statistics Socket Configuration

Serves stats. It's optional; if you don't configure it, joold won't start it.

Sample by command:

```bash
$ joold --stats.address 127.0.0.1 --stats.port 45678
```

Equivalent by file:

```bash
$ cat statsocket.json
{
	"address": "127.0.0.1",
	"port": 45678
}
$ joold --stats statsocket.json
```

It's rudimentary. Sample query:

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
- `NET_SENT_PKTS`: Packets sent to the network. (It should match the remote joold's `NET_RCVD_PKTS`.)
- `NET_SENT_BYTES`: Session bytes sent to the network. (It should match the remote joold's `NET_RCVD_BYTES`.)

Note, because of Linux quirks, `--stats.address=0.0.0.0` does not imply `::`, but `--stats.address=::` implies `0.0.0.0`. If you want the stats served via IPv6 but not IPv4, probably block them by firewall.
