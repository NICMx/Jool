---
layout: documentation
title: Documentación - Parámetros > Pool IPv4
---

[Documentación](esp-doc-index.html) > [Herramienta de configuración de Jool](esp-doc-index.html#aplicacion-de-espacio-de-usuario) > [Flags](esp-usr-flags.html) > \--pool4

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

El pool IPv4 es el subconjunto de direcciones en IPv4, del nodo, que puede ser utilizado para traducir. 

NOTA:
Debido a [fallas en la implementación actual](https://github.com/NICMx/NAT64/issues/117#issuecomment-66942415), evite administrar prefijos de longitudes /24 o menores porque esto demandará mucha memoria y alentará su sistema.  


## Sintaxis

	jool --pool4 [--display]
	jool --pool4 --count
	jool --pool4 --add <IPv4 prefix>
	jool --pool4 --remove <IPv4 prefix> [--quick]
	jool --pool4 --flush [--quick]

## Opciones

### Operaciones

* `--display`: Lista los prefijos dados de alta y activos del pool. Operación por Omisión
* `--count`: Lista la cantidad de prefijos dados de alta y activos del pool.
* `--add`: Añade todas las direcciones de `<IPv4 prefix>` al pool.
* `--remove`: Borra del pool todas las direcciones de `<IPv4 prefix>`.
* `--flush`: Remueve todas las direcciones del pool.


El valor por omisión de la longitud de `<IPv4 prefix>` es 32, asi que puedes añadir o remover direcciones en lugar de prefijos.

### \--quick

Ve [`--quick`](esp-usr-flags-quick.html).

## Ejemplos

Muestra las direcciones actuales:

	$ jool --pool4 --display
	192.0.2.1/32
	198.51.100.1/32
	203.0.113.8/32
	  (Fetched 3 prefixes.)

Cuántos prefijos están dados de alta:

	$ jool --pool4 --count
	3

Remueve un par de registros:

	# jool --pool4 --remove 192.0.2.1
	# jool --pool4 --remove 198.51.100.1

Añade de nuevo solo uno de ellos:

	# jool --pool4 --add 192.0.2.1
