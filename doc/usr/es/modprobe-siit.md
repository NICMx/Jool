---
language: es
layout: default
category: Documentation
title: Argumentos de SIIT Jool (módulo)
---

[Documentación](documentation.html) > [Argumentos de los módulos de kernel](documentation.html#argumentos-de-los-mdulos-de-kernel) > `jool_siit`

# Argumentos de SIIT Jool (módulo)

## Índice

1. [Sintaxis](#sintaxis)
2. [Ejemplo](#ejemplo)
3. [Argumentos](#argumentos)
	1. [`pool6`](#pool6)
	2. [`blacklist`](#blacklist)
	3. [`pool6791`](#pool6791)
	4. [`disabled`](#disabled)

## Sintaxis

	# /sbin/modprobe jool_siit \
			[pool6=<Prefijo de IPv6>] \
			[blacklist=<Prefijos de IPv4>] \
			[pool6791=<Prefijos de IPv4>] \
			[disabled]

## Ejemplo

	# /sbin/modprobe jool_siit \
			pool6=64:ff9b::/96 \
			blacklist=192.0.2.0,192.0.2.1/32,192.0.2.4/30,192.0.2.16/28,192.0.2.64/26 \
			pool6791="203.0.113.0/24, 198.51.100.0/24" \
			disabled

## Argumentos

Las longitudes de prefijo por defecto son 32 para IPv4 y 128 para IPv6.

Argumentos que consistan en elementos separados por comas pueden contener hasta 5 integrantes. Si se necesitan más, es necesario recurrir a la aplicación de espacio de usuario.

### `pool6`

- Nombre: Pool de IPv6
- Tipo: Prefijo IPv6
- Contraparte de la aplicación de espacio de usuario: [`--pool6`](usr-flags-pool6.html)
- Valor por defecto: Vacío

El prefijo de traducción del RFC 6052. Es el prefijo que Jool va a estar agregando y removiendo de los paquetes de acuerdo a lo descrito en la [introducción a SIIT básico](intro-xlat.html#siit-tradicional).

La longitud del prefijo debe ser 32, 40, 48, 56, 64 o 96 (de acuerdo al RFC 6052).

### `blacklist`

- Nombre: Lista negra de prefijos IPv4
- Tipo: Lista de direcciones/prefijos separados por comas
- Contraparte de la aplicación de espacio de usuario: [`--blacklist`](usr-flags-blacklist.html)
- Valor por defecto: Vacío

Direcciones de IPv4 a excluir de traducción basada en [`pool6`](#pool6).

### `pool6791`

- Nombre: RFC 6791 pool
- Tipo: Lista de direcciones/prefijos separados por comas
- Contraparte de la aplicación de espacio de usuario: [`--pool6791`](usr-flags-pool6791.html)
- Valor por defecto: Vacío

Direcciones con las cuales originar errores ICMPv6 que no tengan fuente traducible. Ver el [resumen del RFC 6791](rfc6791.html).

Cuando la pool está vacía, Jool utiliza las direcciones de su propio nodo como fuente.

### `disabled`

- Nombre: Insertar a Jool, pero no traducir aún.
- Tipo: -
- Contraparte de la aplicación de espacio de usuario: [`--enable` y `--disable`](usr-flags-global.html#enable---disable)

Comienza a Jool inactivo. Si se está usando la aplicación de usuario, se puede usar para asegurar que la configuración está completa antes de que el tráfico comience a ser traducido.

Si no está presente, Jool comienza a traducir tráfico inmediatamente.

