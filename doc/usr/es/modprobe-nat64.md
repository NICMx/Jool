---
language: es
layout: default
category: Documentation
title: Argumentos de NAT64 Jool (módulo)
---

[Documentación](documentation.html) > [Argumentos de los módulos de kernel](documentation.html#argumentos-de-los-mdulos-de-kernel) > `jool`

# Argumentos de NAT64 Jool (módulo)

## Índice

1. [Sintaxis](#sintaxis)
2. [Ejemplo](#ejemplo)
3. [Argumentos](#argumentos)
	1. [`pool6`](#pool6)
	2. [`pool4`](#pool4)
	3. [`disabled`](#disabled)

## Sintaxis

	# /sbin/modprobe jool \
			[pool6=<Prefijo IPv6>] \
			[pool4=<Prefijos IPv4>] \
			[disabled]

## Ejemplo

	# /sbin/modprobe jool \
			pool6=64:ff9b::/96 \
			pool4="198.51.100.1, 203.0.113.0/28" \
			disabled

## Argumentos

Las longitudes de prefijo por defecto son 32 para IPv4 y 128 para IPv6.

Argumentos que consistan en elementos separados por comas pueden contener hasta 5 integrantes. Si se necesitan más, es necesario recurrir a la aplicación de espacio de usuario.

### `pool6`

- Nombre: Pool de IPv6
- Tipo: Prefijo IPv6
- Contraparte de la aplicación de espacio de usuario: [`--pool6`](usr-flags-pool6.html)
- Valor por defecto: -

El prefijo de traducción del RFC 6052. Define la representación IPv6 de las direcciones de los nodos de IPv4; ver la [introducción a NAT64](intro-nat64.html#stateful-nat64).

Jool no puede traducir si este valor no está presente. Por lo tanto, es posible usar el valor por defecto para pausar la traducción, similar a [`disabled`](#disabled).

La longitud del prefijo debe ser 32, 40, 48, 56, 64 o 96 (de acuerdo al RFC 6052).

### `pool4`

- Nombre: Pool de direcciones de transporte de IPv4
- Tipo: Lista de direcciones/prefijos separados por comas
- Contraparte de la aplicación de espacio de usuario: [`--pool4`](usr-flags-pool4.html)
- Valor por defecto: Rango de puertos 61001-65535 de las direcciones que le pertenecen al nodo.

Direcciones de IPv4 con las cuales enmascarar a los nodos de IPv6. Ver [Pool de direcciones de transporte](pool4.html) de IPv4 para encontrar detalles.

Cualquier dirección que se inserte mediante `pool4` utiliza la marca cero, el rango de puertos 1-65535 y los identificadores de ICMP 0-65535. No es posible modificar estos valores durante el modprobe, por lo que se recomienda usar la contraparte de espacio de usuario en lugar de `pool4`.

### `disabled`

- Nombre: Insertar a Jool, pero no traducir aún.
- Type: -
- Contraparte de la aplicación de espacio de usuario: [`--enable` y `--disable`](usr-flags-global.html#enable---disable)

Comienza a Jool inactivo. Si se está usando la aplicación de usuario, se puede usar para asegurar que la configuración está completa antes de que el tráfico comience a ser traducido.

Si no está presente, Jool comienza a traducir tráfico inmediatamente.

