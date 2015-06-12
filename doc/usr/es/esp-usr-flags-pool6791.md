---
layout: documentation
title: Documentación - Parámetros > Direcciones de error
---

[Documentación](esp-doc-index.html) > [Aplicación de espacio de usuario](esp-doc-index.html#aplicacin-de-espacio-de-usuario) > [Parámetros](esp-usr-flags.html) > \--pool6791

# \--pool6791

## Índice

1. [Descripción](#descripcion)
2. [Sintaxis](#sintaxis)
3. [Opciones](#opciones)
4. [Ejemplos](#ejemplos)

## Descripción

Interactua con el [pool RFC 6791](misc-rfc6791.html) de Jool. El pool define direcciones para origenes en errores ICMP intraducibles.

Si el pool está vacio, Jool retrocederá a utilizar las direcciones de su nodo para estos casos.


## Sintaxis

	jool_siit --pool6791 [--display]
	jool_siit --pool6791 --count
	jool_siit --pool6791 --add <IPv4 prefix>
	jool_siit --pool6791 --remove <IPv4 prefix>
	jool_siit --pool6791 --flush

## Opciones

- `--display`: Los prefijos del pool son impresos en la salida estandar. Esta es la operación por default.
- `--count`: El número de _direcciones_ (no prefijos) en el pool es impreso en la salida estandar.  
Por ejemplo, si todo lo que tienes es un prefijo /24, espera "256" como salida.
- `--add`: Carga `<IPv4 prefix>` al pool.
- `--remove`: Borra el prefijo `<IPv4 prefix>` del pool.
- `--flush`: Remueve todos los prefijos del pool.

## Ejemplos

Despliega los prefijos actuales:

	$ jool_siit --pool6791 --display
	192.0.2.0/24
	198.51.100.0/26
	203.0.113.16/28
	  (Fetched 3 prefixes.)

Esto significa que la direccion de origen de un normalmente intraducible error ICMP va a ser cualquiera dentro de los siguientes rangos: 192.0.2.0-192.0.2.255, 198.51.100.0-198.51.100.64, o 203.0.113.16-203.0.113.31.

Despliega solo el conteo de prefijos:

	$ jool_siit --pool6791 --count
	336

(Eso es /24 + /26 + /28 = 256 + 64 + 16.)

Remueve un prefijo:

	$ jool_siit --pool6791 --remove 192.0.2.0/24

Devuelvelo:

	$ jool_siit --pool6791 --add 192.0.2.0/24

Destruye todos los prefijos. Jool empezará a utilizar las direcciones de su host como origen.

	$ jool_siit --pool6791 --flush
