---
language: es
layout: default
category: Documentation
title: --pool6791
---

[Documentación](documentation.html) > [Aplicación de espacio de usuario](documentation.html#aplicacin-de-espacio-de-usuario) > [Parámetros](usr-flags.html) > \--pool6791

# \--pool6791

## Índice

1. [Descripción](#descripcion)
2. [Sintaxis](#sintaxis)
3. [Opciones](#opciones)
4. [Ejemplos](#ejemplos)

## Descripción

Interactúa con el [pool del RFC 6791](rfc6791.html) de Jool. El pool define direcciones para orígenes en errores ICMP intraducibles.

Si el pool está vacío, Jool retrocederá a utilizar las direcciones de su nodo para estos casos.


## Sintaxis

	jool_siit --pool6791 [--display]
	jool_siit --pool6791 --count
	jool_siit --pool6791 --add <IPv4 prefix>
	jool_siit --pool6791 --remove <IPv4 prefix>
	jool_siit --pool6791 --flush

## Opciones

- `--display`: Los prefijos del pool son impresos en salida estándar. Esta es la operación por defecto.
- `--count`: El número de _direcciones_ (no prefijos) en el pool es impreso en salida estándar.  
Por ejemplo, si todo lo que tienes es un prefijo /24, espera "256" como salida.
- `--add`: Carga `<IPv4 prefix>` al pool.
- `--remove`: Borra el prefijo `<IPv4 prefix>` del pool.
- `--flush`: Remueve todos los prefijos del pool.

## Ejemplos

Desplegar los prefijos actuales:

	$ jool_siit --pool6791 --display
	192.0.2.0/24
	198.51.100.0/26
	203.0.113.16/28
	  (Fetched 3 prefixes.)

Esto significa que la dirección de origen de un error ICMP intraducible va a ser cualquiera de los siguientes rangos: 192.0.2.0-192.0.2.255, 198.51.100.0-198.51.100.64, o 203.0.113.16-203.0.113.31.

Desplegar solo el conteo de prefijos:

	$ jool_siit --pool6791 --count
	336

(Eso es /24 + /26 + /28 = 256 + 64 + 16.)

Remover un prefijo:

	$ jool_siit --pool6791 --remove 192.0.2.0/24

Devolverlo:

	$ jool_siit --pool6791 --add 192.0.2.0/24

Destruir todos los prefijos. Jool empezará a utilizar las direcciones de su host como origen.

	$ jool_siit --pool6791 --flush

