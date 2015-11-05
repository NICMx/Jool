---
language: es
layout: default
category: Documentation
title: Documentación - Índice
---

# Documentación

Bienvenido/a al índice de la documentación de Jool.

## Introducción

1. [¿Qué es SIIT/NAT64?](intro-xlat.html)
2. [¿Qué es Jool?](intro-jool.html)

Ver el [RFC 6586](https://tools.ietf.org/html/rfc6586) para encontrar experiencias de despliegue usando Stateful NAT64.

## Instalación

1. [Módulos de kernel](install-mod.html)
2. [Aplicaciones de espacio de usuario](install-usr.html)

## Ejemplos de uso

1. [SIIT](run-vanilla.html)
2. [SIIT + EAM](run-eam.html)
3. [Stateful NAT64](run-nat64.html)
4. [DNS64](dns64.html)

## SIIT en detalle

1. [La EAMT](eamt.html)
2. [Direcciones de IPv6 intraducibles](pool6791.html)

## NAT64 en detalle

1. [La pool de direcciones de transporte IPv4](pool4.html)
2. [BIB](bib.html)

## Argumentos de los módulos de kernel

1. [`jool_siit`](modprobe-siit.html)
2. [`jool`](modprobe-nat64.html)

## Aplicación de Espacio de Usuario

1. Argumentos en común
	1. [`--help`](usr-flags-help.html)
	2. [`--global`](usr-flags-global.html)
		1. [`--plateaus`](usr-flags-plateaus.html)
	3. [`--pool6`](usr-flags-pool6.html)
2. Argumentos exclusivos de `jool_siit`
	1. [`--eamt`](usr-flags-eamt.html)
	2. [`--blacklist`](usr-flags-blacklist.html)
	3. [`--pool6791`](usr-flags-pool6791.html)
3. Argumentos exclusivos de`jool`
	1. [`--pool4`](usr-flags-pool4.html)
	2. [`--bib`](usr-flags-bib.html)
	3. [`--session`](usr-flags-session.html)
	4. [`--quick`](usr-flags-quick.html)

## Arquitecturas definidas

1. [SIIT-DC](siit-dc.html)
2. [464XLAT](464xlat.html)
3. [SIIT-DC: Modo de traducción dual](siit-dc-2xlat.html)

## Otro ejemplos de uso

1. [Interfaz única](single-interface.html)
2. [Traducción local](node-based-translation.html)

## Misceláneos

1. [FAQ](faq.html)
2. [Logging](logging.html)
3. [MTU y fragmentación](mtu.html)
4. [Offloads](offloads.html)

