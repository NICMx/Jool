---
layout: documentation
title: Documentación - Parámetros > Pool IPv4
---

[Documentación](esp-doc-index.html) > [Aplicación de espacio de usuario](esp-doc-index.html#aplicacin-de-espacio-de-usuario) > [Parámetros](esp-usr-flags.html) > \--blacklist

# \--blacklist

## Índice

1. [Descripción](#descripcion)
2. [Sintaxis](#sintaxis)
3. [Opciones](#opciones)
4. [Ejemplos](#ejemplos)

## Descripción

Interactua con el pool de direcciones que se encuentran en la lista negra de Jool.

El pool dicta que direcciones pueden ser traducidas utilizando el prefijo [pool6](usr-flags-pool6.html). Toma en cuenta que [EAM](esp-usr-flags-eamt.html) tiene mas prioridad que el prefijo, asi que no tienes que agregar un registro a este pool para cada registro EAM que necesitas.

Hay algunas direcciones que Jool se reusará a traducir, independientemente de `blacklist`. Estas incluyen

- Las direcciones que pertenecen al nodo de Jool (por que Jool solo puede utilizarse en modo de redirecionamiento, actualmente).
- Direcciones de Software (0.0.0.0/8).
- Direcciones de Host (127.0.0.0/8).
- Direcciones de enlace local (169.254.0.0/16).
- Broadcast limitado (255.255.255.255/32).

## Sintaxis

	jool_siit --blacklist [--display]
	jool_siit --blacklist --count
	jool_siit --blacklist --add <IPv4 prefix>
	jool_siit --blacklist --remove <IPv4 prefix>
	jool_siit --blacklist --flush

## Opciones

* `--display`: Los prefijos de las direcciones del Pool son impresos en la salida estandar. Esta es la operación por default.
* `--count`: El número de _direcciones_ (no prefijos) en el pool es impreso en la salida estandar.  
Por ejemplo, si todo lo que tienes es un prefijo /30, espera "4" como.
* `--add`: Carga `<IPv4 prefix>` al pool.
* `--remove`: Borra la dirección `<IPv4 prefix>` de las tablas.
* `--flush`: Remueve todas las direcciones/prefijos del pool.

## Ejemplos

Despliega las direcciones actuales:

	$ jool_siit --blacklist --display
	192.0.2.0/28
	198.51.100.0/30
	203.0.113.8/32
	  (Fetched 3 prefixes.)

Despliega solo el conteo de direcciones:

	$ jool_siit --blacklist --count
	21

(That's /28 + /30 + /32 = 16 + 4 + 1)

Remueve un par de entradas:

	# jool_siit --blacklist --remove 192.0.2.0/28
	# jool_siit --blacklist --remove 198.51.100.0/30

Devuelve una entrada:

	# jool_siit --blacklist --add 192.0.2.0/28
