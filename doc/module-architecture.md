# Architecture

This is an introduction to the kernel module's source files and their relationships. Think of one of the [networking stacks](https://en.wikipedia.org/wiki/OSI_model#Description_of_OSI_layers) when you see this diagram:

	+------------------------------------------+
	|                 Global                   |
	+-------------------+----------------------+
	| Translation Steps | Netlink Multiplexing |
	+-------------------+----------------------+
	|            Translation Meta              |
	+-------------------+----------------------+
	|               Databases                  |
	+------------------------------------------+
	|                 Utils                    |
	+------------------------------------------+

Files are allowed to depend on any files from *the same* or lower layers. They should not depend on files from next nor upper layers. Nothing really enforces this but please follow the rules so the code remains as approachable as possible.

All the files can be found in either `module/`, `module/common/`, `module/nat64/` or `module/siit/`.

## Global layer

The shell of Jool. Where everything starts and ends. The layer that stands immediately between the kernel and Jool. If you want to overall read the code, you probably want to start from here.

- `initialization.c` (The routines that hook and unhook Jool to the kernel when you modprobe.)
- `core.c` (What happens every time the kernel posts a packet on Jool.)
- `nl-handler.c` (The entry point for userspace application commands.)
- `timer.c` (A timer that does a bit of maintenance every now and then.)

## Translation Steps layer

This is the global translation pipeline. If you see the index of RFC 6146, you will notice that most of the first-tier files here are simply the steps listed there.

- `packet-init.c`
- `determine-incoming-tuple.c`
- `filtering-and-updating.c`
- `compute-outgoing-tuple.c`
- `rfc7915/*` ("Translating the Packet" step - RFC 7915 obsoletes RFC 6145.) This also involves the utility (ie. databaseless) address translation modules:
	- `rfc6052.c`
	- `rfc6791.c`
- `handling-hairpinning.c`

> (`send-packet` could also be considered a translation step, but also passes for a basic operation. BIB is RFC-bound to depend on it, so I decided to demote it down to Utils.)

## Netlink Multiplexing

There is one of these for every userspace application configuration mode, and they take care of redirecting/formatting requests to each database module.

- `nl/*`

## Translation Meta layer

The "Utils" layer of the upper layers.

- `xlator.c` (A *translator* instance. An object that contains the Jool instance (ie. databases) that should be used during a given translation.)
- `xlation.c` (An "object" that contains a bunch of meta regarding a given ongoing *translation*)

## Databases layer

Lots of data here. Concurrence-sensitive code; handle with forceps.

- `bib/db.c` (The BIB)
- `pool4/db.c` (The NAT64 IPv4 transport address pool)
- `eam.c` (RFC 7757)
- `atomic-config.c`
- `config.c` (`--global` configuration)
- `joold.c`

## Utils layer

Lots of functions that can be either recklessly called from anywhere or are basic database templates that rely on upper-layer locking.

- `address`
- `error-pool`
- `hash-table`
- `icmp-wrapper`
- `ipv6-hdr-iterator`
- `linux-version`
- `log`
- `module-stats`
- `module-types`
- `nl-buffer`
- `packet`
- `rbtree`
- `rcu`
- `rtrie`
- `send-packet`
- `str-utils`
- `tags`
- `wkmalloc`
- `xlat`

## TODO

The following modules belong to lower layers, but currently depend on Translation Meta:

- `rfc6056`
- `pool4/db`
- `bib/db`
