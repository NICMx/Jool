---
language: es
layout: default
category: Documentation
title: --blacklist
---

[Documentación](documentation.html) > [Aplicación de espacio de usuario](documentation.html#aplicacin-de-espacio-de-usuario) > [Parámetros](usr-flags.html) > \--blacklist

# \--blacklist

## Índice

1. [Descripción](#descripcion)
2. [Sintaxis](#sintaxis)
3. [Opciones](#opciones)
4. [Ejemplos](#ejemplos)

## Descripción

Interactúa con el pool de direcciones que se encuentran en la lista negra de Jool.

El pool dicta qué direcciones pueden ser traducidas utilizando el prefijo [pool6](usr-flags-pool6.html). [EAM](usr-flags-eamt.html) tiene más prioridad que el prefijo, de modo que no es necesario agregar un registro a este pool para cada registro EAMT.

Hay algunas direcciones que Jool se reusará a traducir, independientemente de `blacklist`. Estas incluyen

- Las direcciones que pertenecen al nodo de Jool.
- Direcciones de Software (0.0.0.0/8).
- Direcciones de Host (127.0.0.0/8).
- Direcciones de enlace local (169.254.0.0/16).
- Multicast (224.0.0.0/4).
- Broadcast limitado (255.255.255.255/32).

## Sintaxis

	jool_siit --blacklist [--display]
	jool_siit --blacklist --count
	jool_siit --blacklist --add <IPv4 prefix>
	jool_siit --blacklist --remove <IPv4 prefix>
	jool_siit --blacklist --flush

## Opciones

* `--display`: Los prefijos de las direcciones de blacklist son impresos en salida estándar. Esta es la operación por defecto.
* `--count`: El número de _direcciones_ (no prefijos) en el pool es impreso en salida estándar.  
  Por ejemplo, si todo lo que tienes es un prefijo /30, espera "4" como resultado.
* `--add`: Carga `<IPv4 prefix>` al pool.
* `--remove`: Borra la dirección `<IPv4 prefix>` del pool.
* `--flush`: Remueve todas las direcciones/prefijos del pool.

## Ejemplos

Desplegar las direcciones actuales:

	$ jool_siit --blacklist --display
	192.0.2.0/28
	198.51.100.0/30
	203.0.113.8/32
	  (Fetched 3 prefixes.)

Desplegar el conteo de direcciones:

	$ jool_siit --blacklist --count
	21

(Eso es /28 + /30 + /32 = 16 + 4 + 1)

Remover un par de entradas:

	# jool_siit --blacklist --remove 192.0.2.0/28
	# jool_siit --blacklist --remove 198.51.100.0/30

Devolver una entrada:

	# jool_siit --blacklist --add 192.0.2.0/28

