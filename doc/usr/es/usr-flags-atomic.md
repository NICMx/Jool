---
language: es
layout: default
category: Documentation
title: Fragmentos Atómicos
---

[Documentation](documentation.html) > [Herramienta de configuración de Jool](documentation.html#Aplicacion-de-espacio-de-usuario) > [Flags](usr-flags.html) > [\--global](usr-flags-global.html) > Fragmentos Atómicos

# Fragmentos Atómicos

## Índice

1. [Introducción](#overview)
2. [Parámetros](#flags)
	1. [`--allow-atomic-fragments`](#allowatomicfragments)
	2. [`--setDF`](#setdf)
	3. [`--genFH`](#genfh)
	4. [`--genID`](#genid)
	5. [`--boostMTU`](#boostmtu)

## Introducción

Los "Fragmenos Atómicos" son por decirlo de otra manera "Fragmentos Aislados"; es decir, son paquetes de IPv6 que poseen un _fragment header_ sin que éste realmente sea un segmento de un paquete mayor. Son un hack en la especificación de traducción IP/ICMP que busca compensar por la diferencia entre el mínimo MTU entre los protocolos (68 para IPv4, 1280 para IPv6).

Se conoce actualmente que los fragmentos atómicos tienen [implicaciones adversas de seguridad](https://tools.ietf.org/html/rfc6946) y [están siendo deprecados](https://tools.ietf.org/html/draft-ietf-6man-deprecate-atomfrag-generation-00). Incluso el RFC 6145 (el documento principal de SIIT) advierte sobre [problemas relacionados con el hack](http://tools.ietf.org/html/rfc6145#section-6).

Desde la perspectiva de Jool, como no se ha oficializado su desuso, estos aún siguen presentes en la implementación. Sin embargo, se han observado problemas técnicos al permitir los fragmentos atómicos. El kernel de Linux no está pensado para identificar cabeceras de fragmento redundantes en tráfico generado localmente, de modo que puede añadir otra adicional:

[![Fig.1 - ¿Qué podría salir mal?](../images/atomic-double-frag.png)](obj/atomic-double-frag.pcapng "¿Qué podría salir mal?")

En **Jool 3.2 y en versiones anteriores** se solía evadir este problema evitando delegar la fragmentación al kernel; sin embargo, esto trae otros problemas más sutiles.

En **Jool 3.3** y **3.4** el problema se evade deshabilitando los fragmentos atómicos por defecto; modificar esta configuración **no** es recomendado. Las opciones presentadas en este documento están deprecadas, y se eliminarán una vez [deprecate-atomfrag-generation]({{ site.draft-deprecate-atomfrag-generation }}) sea promovido a RFC.

## Parámetros

		
### `--allow-atomic-fragments`
	
- Nombre: ***¿Permitir fragmentos atómicos?***
- Tipo: ***Booleano***
- Valor por Omisión: ***Apagado(0)***
- Modos: ***SIIT & Stateful***
- Sentido de traducción: ***IPv4 -> IPv6 & IPv6 -> IPv4***

Esta bandera sumariza la acción de las otras cuatro banderas (`--setDF`, `--genFH`, `--genID` y `--boostMTU`) con el propósito de habilitar o deshabilitar la recepción y traducción de fragmentos atómicos.

Para habilitar fragmentos atómicos, ejecutar:

{% highlight bash %}
jool --allow-atomic-fragments true
{% endhighlight %}

Lo cual es equivalente a

{% highlight bash %}
jool --setDF true
jool --genFH true
jool --genID false
jool --boostMTU false
{% endhighlight %}

Según lo establece el [RFC 6145 (sección 6)](http://tools.ietf.org/html/rfc6145#section-6) este debería ser el comportamiento por defecto. [deprecate-atomfrag-generation]({{ site.draft-deprecate-atomfrag-generation }}) está deprecándolo, en favor de

{% highlight bash %}
jool --allow-atomic-fragments false
{% endhighlight %}

Lo cual es equivalente a:

{% highlight bash %}
jool --setDF false
jool --genFH false
jool --genID true
jool --boostMTU true
{% endhighlight %}

Notas:

1. La separación de los cuatro parámetros existe por razones históricas en la implementación, mas en el avance del proyecto se ha visto que no tiene sentido manejarlos individualmente.
2. La relación entre `--setDF` y `--boostMTU` es delicada. Consultar abajo para encontrar más detalles.


### `--setDF`

- Nombre: ***¿Tratar siempre de encender la bandera DF?***
- Tipo: ***Booleano***
- Valor por Omisión: ***Apagado (0)***
- Modos: ***SIIT & Stateful***
- Sentido de traducción: ***IPv6 -> IPv4***

La lógica descrita en forma de pseudocódigo es:
          
	Si el paquete IPv6 entrante tiene una cabecera de fragmento:
		DF es cero
	En caso contrario:
		Si --setDF está encendido:
			DF es uno
		En caso contrario:
			Si la longitud del paquete saliente es > 1260:
				DF es uno
			En caso contrario:
				DF es cero

Notas:

1. El razonamiento está explicado en la [Sección 6 del RFC 6145](http://tools.ietf.org/html/rfc6145#section-6).
2. El número 1260 viene de el mínumo MTU de IPv6 (1280) - longitud del encabezado de IPv6 (40) + longitud del encabezado de IPv4 (20).


### `--genFH`

- Nombre: ***¿Generar [Fragment Header](https://tools.ietf.org/html/rfc2460#section-4.5)?***
- Tipo: ***Booleano***
- Valor por Omisión: ***Apagado (0)***
- Modos: ***SIIT & Stateful***
- Sentido de traducción: ***IPv4 -> IPv6***

En pseudocódigo:

	Si el paquete IPv4 entrante es un fragmento:
		El paquete saliente será un fragmento.
		(y por lo tanto incluirá Fragment Header.)
	En caso contrario:
		Si la bandera DF del paquete entrante está encendida
			no se incluirá un Fragment Header
		En caso contrario:
			Si --genFH está encendido:
				sí se incluirá un Fragment Header
			En caso contrario:
				no se incluirá un Fragment Header

Este es el parámetro que causa que Linux se comporte erróneamente cuando necesita fragmentar. No funciona bien, de modo que no se recomienda activar.


### `--genID`

- Nombre: ***GENERA IDENTIFICACIÓN IPV4***
- Tipo: ***Booleano***
- Valor por Omisión: ***Encendido (1)***
- Modos: ***SIIT & Stateful***
- Sentido de traducción: ***IPv6 -> IPv4***

Los paquetes IPv6 solo disponen de un campo de identificación si son fragmentos; es decir, si tienen una cabecera de fragmento. Sin embargo, todos los paquetes de IPv4 deben de llevar un campo de identificación. Esta bandera sirve para especificarle a Jool qué hacer con este campo cuando traduce un paquete (de IPv4 a IPv6) que carece de identificador.

La lógica descrita en forma de pseudocódigo es:

	Si el paquete entrante tiene una cabecera de fragmento:
		El identificador de fragmento se copia del paquete entrante al saliente.
	En caso contrario:
		Si --genID está activado:
			El identificador de fragmento se generará aleatoriamente.
		En caso contrario:
			El identificador de fragmento será cero.

### `--boostMTU`

- Nombre: ***PROMUEVE MTU IPv6***
- Tipo: ***Booleano***
- Valor por Omisión: ***Encendido (1)***
- Modes: ***SIIT && Stateful***
- Dirección de traducción: ***IPv4 -> IPv6 (aplica en: msg. de error de ICMP)***

Cuando un paquete es demasiado grande para el MTU de un enlace, los routers en IPv4 generan mensajes ICMP de error -[Fragmentation Needed](http://tools.ietf.org/html/rfc792)- en IPv4 que pudieran ser traducidos como  -[Packet too Big](http://tools.ietf.org/html/rfc4443#section-3.2)- en IPv6.

Estos errores ICMP se supone deben contener el MTU infractor para que el emisor pueda reajustar el tamaño de sus paquetes. Dado que el MTU mínimo para IPv4 es 68 bytes y el de IPv6 es 1280, Jool puede encontrarse queriendo reportar un MTU illegal en IPv6 al traducir un _Fragmentation Needed_ (v4) en un _Packet too Big_ (v6). `--boostMTU` dicta qué hacer en estos casos.

La validación descrita en forma de pseudocódigo es:

	MTU del paquete saliente IPv6 = MTU del paquete entrante IPv4 + 20
	Si --boostMTU == 1 y el MTU del paquete saliente IPv6 < 1280:
		MTU del paquete saliente IPv6 = 1280

(el `+ 20` compensa por la diferencia entre los tamaños de los encabezados de IPv6 e IPv4.)

Para mayor información ver la [sección 6 del RFC 6145](http://tools.ietf.org/html/rfc6145#section-6).

**AVISO:**

Si `--setDF` y `--boostMTU` están ambos encendidos y hay un enlace IPv4 con MTU &lt; 1260, se llega a establecer un bucle infinito similar al [problema de MTU](mtu.html):

1. El emisor IPv6 transmite un paquete de tamaño 1280.
2. Jool lo traduce en un paquete IPv4 de tamaño 1260 con DF=1
3. Un router IPv4 con interfaz de salida con MTU &lt; 1260 genera _ICMPv6 Frag Needed_ con MTU=1000 (o algún otro).
4. Jool lo traduce a ICMPv6 _Packet Too Big_ con MTU=1280.
5. Ve al punto 1.

