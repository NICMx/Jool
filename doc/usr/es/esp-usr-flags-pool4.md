---
layout: documentation
title: Documentación - Parámetros > Pool IPv4
---

[Documentación](esp-doc-index.html) > [Aplicación de espacio de usuario](esp-doc-index.html#aplicacin-de-espacio-de-usuario) > [Flags](esp-usr-flags.html) > \--pool4

# \--pool4

## Índice

1. [Descripción](#descripcion)
2. [Sintaxis](#sintaxis)
3. [Opciones](#opciones)
   1. [Operaciones](#operaciones)
   2. [`--quick`](#quick)
4. [Ejemplos](#ejemplos)

## Descripción

Interactua con el Pool IPv4 de Jool.

El pool IPv4 es el subconjunto de la dirección del nodo que deberia se utilizado para traducir. 

Ya que la implementación actual [deja mucho que desear](https://github.com/NICMx/NAT64/issues/117#issuecomment-66942415), editar el pool es muy lento y demanda mucha memoria. Quieres evitar administrar prefijos de longitudes /24 y mas abajo en este caso.  


## Sintaxis

	jool --pool4 [--display]
	jool --pool4 --count
	jool --pool4 --add <IPv4 prefix>
	jool --pool4 --remove <IPv4 prefix> [--quick]
	jool --pool4 --flush [--quick]

## Opciones

### Operaciones

* `--display`: Las direcciones del pool son impresas en la salida estandar. Esta es la operación por default.
* `--count`: El número de direcciones en el pool es impreso en la salida estandar.
* `--add`: Carga todas las direcciones de `<IPv4 prefix>` al pool.
* `--remove`: Borra del pool todas las direcciones de `<IPv4 prefix>`.
* `--flush`: Remueve todas las direcciones del pool.


La longitud de `<IPv4 prefix>` es 32 por default, asi que puedes añadir o remover direcciones en lugar de prefijos.

### \--quick

Ve [`--quick`](esp-usr-flags-quick.html).

## Ejemplos

Despliega las direcciones actuales:

	$ jool --pool4 --display
	192.0.2.1/32
	198.51.100.1/32
	203.0.113.8/32
	  (Fetched 3 prefixes.)

Despliega solo el conteo de direcciones:

	$ jool --pool4 --count
	3

Remueve un par de registros:

	# jool --pool4 --remove 192.0.2.1
	# jool --pool4 --remove 198.51.100.1

Devuelve un registro:

	# jool --pool4 --add 192.0.2.1
