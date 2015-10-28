---
language: en
layout: default
category: Documentation
title: --help
---

[Documentation](documentation.html) > [Userspace Application Arguments](documentation.html#userspace-application-arguments) > \--help

# \--help

## Index

1. [Description](#description)
2. [Syntax](#syntax)
3. [Examples](#examples)

## Description

Prints mostly a summary of the [userspace app flags documentation](documentation.html#userspace-application-arguments), though you can also use it to review the abbreviated form of the flags, which aren't there.

`--help` is the only mode which does not require the respective kernel module to be active.

You might also be interested in `man jool_siit`/`man jool`, which prints a better summary of the grammar.

## Syntax

	(jool_siit | jool) --help

## Examples

	jool_siit --help
	jool --help

