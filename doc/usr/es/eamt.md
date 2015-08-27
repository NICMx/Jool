---
language: es
layout: default
category: Documentation
title: EAMT
---

[Documentación](documentation.html) > [Ejemplos de uso](documentation.html#ejemplos-de-uso) > [SIIT + EAM](mod-run-eam.html) > EAMT

# EAMT

## Índice

1. [Definición](#definicion)
2. [Ejemplos] (#ejemplos)
	1. [`Registro 01`] (#registro-01)
	2. [`Registro 02`] (#registro-02)
	3. [`Registro 03`] (#registro-03)
3. [Resumen y Notas Adicionales] (#resumen-notas-adicionales)
	
## Definición

La tabla EAMT (_Explicit Address Mappings Table_) por sus siglas en inglés, es una colección de registros en un servidor SIIT y en ella se guarda la relación de cómo las diferentes direcciones deben de ser traducidas. 

Lo que distingue este tipo de mapeo con los otros mecanismos es, en que la dirección IPv4 no forma parte de la dirección IPv6 a usar.

## Ejemplos

Aquí se encuentra un ejemplo de una tabla EAMT:

| No.Registro|   Prefijo IPv4  |     Prefijo IPv6     |
|----------- |-----------------|----------------------|
|    01      | 192.0.2.1/32    | 2001:db8:aaaa::5/128 |
|    02      | 198.51.100.0/24 | 2001:db8:bbbb::/120  |
|    03      | 203.0.113.8/29  | 2001:db8:cccc::/125  |

Un registro EAMT está compuesto en pares, un prefijo IPv4 y un prefijo IPv6. Cuando una dirección esta siendo traducida, su prefijo es literalmente reemplazado de acuerdo a la tabla.

			NOTA IMPORTANTE: En la implementación de Jool, todos los registros son bidireccionales.

### Registro 01

Este es el caso más sencillo, porque no tiene prefijo. El registro literalmente dice: "La dirección `192.0.2.1` debe de ser siempre traducida como `2001:db8:aaaa::5`, y a la inversa".

Ya sea que la dirección sea origen, destino o esté dentro del paquete interno de un error ICMP, no importa.

La representación IPv6 de `192.0.2.1` es `2001:db8:aaaa::5`, y la representación IPv4 de `2001:db8:aaaa::5` es `192.0.2.1`.

### Registro 02

La segunda entrada es más interesante, porque hay un byte de sufijo. El registro esta diciendo: "El grupo de direcciones `198.51.100.x` debera ser tradicido como `2001:db8:bbbb::x`, y viceversa. Donde _x_ está en el intervalo de 0-255."

Como en:

- `198.51.100.0` <-> `2001:db8:bbbb::0`
- `198.51.100.1` <-> `2001:db8:bbbb::1`
- `198.51.100.2` <-> `2001:db8:bbbb::2`
- ...
- `198.51.100.254` <-> `2001:db8:bbbb::fe`
- `198.51.100.255` <-> `2001:db8:bbbb::ff`

Esta forma puede ayudarte a simplificar la configuración cuando tienes muchas direcciones a traducir; el sufijo siempre es preservado. La ventaja, que es evidente, es que un solo registro EAMT puede describir la traducción de una red entera.

Por mencionar otro ejemplo, un registro EAMT con /16 será mucho más eficiente que los 65536 registros atómicos equivalentes.

### Registro 03

El reemplazo de prefijo puede ser hecho a nivel de bits. El tercer registro ejemplifica esto, porque son 3 bits de sufijo. El registro esta diciendo: "El grupo de direcciones `203.0.113.x` debera ser tradicido como `2001:db8:cccc::y`, y a la inversa. Donde _x_ = [8,15], _y_ = [0,7]."

La dirección `203.0.113.8` se convierte en `2001:db8:cccc::`, no en `2001:db8:cccc::8`. Esto es porque la forma binaria de `.8` es `00001000`, y la máscara es de 29 por lo que el uno se encuentra en el lado del prefijo.

- `203.0.113.8` <-> `2001:db8:cccc::`
- `203.0.113.9` <-> `2001:db8:cccc::1`
- `203.0.113.10` <-> `2001:db8:cccc::2`
- `203.0.113.11` <-> `2001:db8:cccc::3`
- `203.0.113.12` <-> `2001:db8:cccc::4`
- `203.0.113.13` <-> `2001:db8:cccc::5`
- `203.0.113.14` <-> `2001:db8:cccc::6`
- `203.0.113.15` <-> `2001:db8:cccc::7`

## Resumen y Notas Adicionales

En el mecanisimo de transición SIIT-EAM se emplea y se mantiene la tabla de direcciones de mapeo explicito.

En dicha tabla existen duplas con prefijos de IPv4 e IPv6 válidos.

El prefijo es remplazado a nivel de bits.

La dirección IPv4 no forma parte de la dirección IPv6 a usar.

Los registros son bidireccionales.

Los registros EAMT no se pueden intersectar. 

Los paquetes que empleen dichas direcciones se tratarán como tales, es decir, con ese tipo de traducción.

Si Jool no encuentra una coincidencia en la tabla para una dirección, intenta traducir basado en el prefijo [`pool6`](usr-flags-pool6.html). 

Si eso también falla, el paquete es devuelto al kernel. Se asume que el paquete no debe ser traducido.

Ve la [demostración](mod-run-eam.html) o el [material de referencia](usr-flags-eamt.html) para obtener información de cómo crear y destruir registros manualmente.
