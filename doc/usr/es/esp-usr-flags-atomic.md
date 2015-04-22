
---
layout: documentation
title: Documentación - Flags > Fragmentos Atómicos
---

[Documentation](esp-doc-index.html) > [Aplicación de espacio de usuario](esp-doc-index.html#Aplicacin-de-espacio-de-usuario) > [Flags](esp-usr-flags.html) > [\--global](esp-usr-flags-global.html) > Fragmentos Atómicos

# Fragmentos Atómicos

## Índice

1. [Introducción](#overview)
2. [Parámetros](#flags)
	1. [`--allow-atomic-fragments`](#atomicfragments)
	2. [`--setDF`](#setdf)
	3. [`--genFH`](#genfh)
	4. [`--genID`](#genid)
	5. [`--boostMTU`](#boostmtu)

## Introduccón

Los "Fragmenos Atómicos" son paquetes IPv6 que no están fragmentados pero aun así con tienen una [Cabecera de fragmento](https://tools.ietf.org/html/rfc2460#section-4.5)(reduntante). Son un hack en la especificación NAT64 que intenta tomar ventaja de la diferencia entre el MTU minimo IPv4 (68) y el MTU minimo IPv6 (1280).

Se sabe que los fragmentos atómicos tienen [implicaciones de seguridad](https://tools.ietf.org/html/rfc6946) y hay un [esfuerzo encaminado oficial para deprecarlos](https://tools.ietf.org/html/draft-ietf-6man-deprecate-atomfrag-generation-00). Incluso el RFC 6145 (esto es. el documento principal de SIIT) advierte sobre [problemas con respecto al hack](http://tools.ietf.org/html/rfc6145#section-6).

Desde la perspectiva de Jool, también hay problemas técnicos para permitir los fragmentos atómicos. El kernel de Linux es particularmente deficiente cuando se trata de cabeceras de fragmento, asi que si Jool está generando uno, Linux quizá fragmente el paquete de una manera graciosa:

[![Figure 1 - que podría salir mal?](images/atomic-double-frag.png)](obj/atomic-double-frag.pcapng)

(Jool 3.2 y versiones anteriores solían evadir esto no delegando la fragmentación al kernel, pero esto introdujo otros problemas más sutiles.)

Como consecuencia, la configuración por default de Jool 3.3 **deshabilita** los fragmentos atómicos. Deberías muy probablemente **nunca** cambiar esto. Las opciones descritas despues en este documento todas tienen que ver con fragmentosd atomicos y ahora son consideradas **deprecadas**. De hecho, intentamos removerlas tan pronto como (y si)[draft-ietf-6man-deprecate-atomfrag-generation](https://tools.ietf.org/html/draft-ietf-6man-deprecate-atomfrag-generation-00) es actualizado a un status de RFC.

Que se sepa que aceptamos completamente la deprecación de fragmentos atómicos.

## Parámetros

### `--allow-atomic-fragments`

- Tipo: Booleano
- Default: OFF
- Modos: Ambos (SIIT y Stateful)
- Sentido de traducción: Ambos (IPv4 a IPv6 y IPv6 a IPv4)
- Fuente: [RFC 6145, princpalmente la sección 6](http://tools.ietf.org/html/rfc6145#section-6). Siendo deprecado en [deprecate-atomfrag-generation](https://tools.ietf.org/html/draft-ietf-6man-deprecate-atomfrag-generation-00).

Esta es una versión corta de todos los parámetros siguientes.

Esto:

{% highlight bash %}
$(jool) --allow-atomic-fragments true
{% endhighlight %}

es lo mismo que

{% highlight bash %}
$(jool) --setDF true
$(jool) --genFH true
$(jool) --genID false
$(jool) --boostMTU false
{% endhighlight %}

Este es el comportamiento por default requerido por el [RFC 6145](http://tools.ietf.org/html/rfc6145), y la IETF con suerte lo va a deprecar en el futuro. _No_ es el default de Jool y no lo recomendamos.


También esto

{% highlight bash %}
$(jool) --allow-atomic-fragments false
{% endhighlight %}

es lo mismo que

{% highlight bash %}
$(jool) --setDF false
$(jool) --genFH false
$(jool) --genID true
$(jool) --boostMTU true
{% endhighlight %}

Este es un modo alternativo definido por ambosd el RFC 6145 y el [draft-ietf-6man-deprecate-atomfrag-generation](https://tools.ietf.org/html/draft-ietf-6man-deprecate-atomfrag-generation-00). El último demanda este comportamiento y es el comportamiento por default de Jool 3.3.

Tambien:

La separación de los cuatro parámetros existe solo por razones históricas; nuestra interpretación del RFC solía estar equivocada. Nunca deberias de manejarlos individualmente. No tiene sentido asignar el valor false a `--setDF` y asignar true a `--setFH`, por ejemplo. La relación entre  `--setDF` y `--boostMTU` es tambien particularmente delicada; ve abajo para mas detalles.


### `--setDF`

- Nombre: Parámetro DF siempre encendido
- Tipo: Booleano
- Default: OFF
- Modos: Ambos (SIIT y Stateful)
- Sentido de traducción: IPv6 a IPv4

La lógica es mejor desceita en forma de pseudocódigo:
          
        Si el paquete entrante tiene una cabecera de fragmento:  
		    El parámetro DF del paquete saliente será falso.
		De otra forma:
		   si --setDF es true
            El parámetro DF del paquete saliente será verdadero.
			
			De otra forma:
                Si la longitud del paquete saliente es > 1260
					El parámetro DF del paquete saliente será verdadero.
				De otra forma:
					El parámetro DF del paquete saliente será falso.

La [Sección 6 del RFC 6145](http://tools.ietf.org/html/rfc6145#section-6) describe los fundamentos lógicos.

También ve [`--boostMTU`](#boostmtu) para una mejor comprensión.


### `--genFH`

- Nombre: Generar Cabecera de Fragmento IPv6.
- Tipo: Booleano
- Default: OFF
- Modos: Both (SIIT and Stateful)
- Sentido de traducción: IPv4 ta IPv6

Si este parámetro esta en ON, Jool siempre generará una "cabecera de fragmento IPv6" si el paquete IPv4 entrante no tiene activo el parámetro DF.

Si este esta en OFF, entonces Jool no generará la "cabecera de fragmento IPv6" este o no este activo el parámetro el paquete IPv4 entrante, a menos de que el paquete entrante sea un fragmento, la "cabecera de fragmento IPv6" será generada.

Este es el parámetro que causa que Linux se vuelva loco cuando necesita fragmentar. No funciona bien, asi que activalo bajo tu propio riesgo.


### `--genID`

- Nombre: Generar identificación IPv4
- Tipo: Booleano
- Default: ON
- Modos: Ambos (SIIT y Stateful)
- Sentido de traducción: IPv6 a IPv4

Todos los paquetes IPv4 con tienen un campo de indentificación. Los paquetes IPv6 solo contienen un campo de identificación  si tienen una cabecera de fragmento. 

Si el paquete IPv6 entrante tiene una cabecera de fragmento, el campo de identificación de la [cabecera IPv4](http://en.wikipedia.org/wiki/IPv4#Header) _siempre_ es copiado desde los bits de orden mas bajo del valor del valor de identificación de la cabecera de fragmento IPv6. 

Por otra parte:

- If `--genID` is OFF, the IPv4 header's Identification fields are set to zero.
- If `--genID` is ON, the IPv4 headers' Identification fields are set randomly.

### `--boostMTU`

- Nombre: Decrease MTU failure rate
- Tipo: Booleano
- Default: ON
- Modes: Ambos (SIIT y Stateful)
- Dirección de traducción: IPv4 to IPv6 (solo errores ICMP)

Cuando un paquete es muy grande para el MTU de un enlace, los routers generan mensajes ICMP de error - [Packet too Big](http://tools.ietf.org/html/rfc4443#section-3.2)- en IPv6 y -[Fragmentation Needed](http://tools.ietf.org/html/rfc792)- en IPv4. Estos tipos de error son aproximadamente equivalentes, así que Jool traduce _Packet too Bigs_ en _Fragmentation Neededs_ y vice-versa.

Estos errores ICMP se supone deben contener el MTU infractor para que el emisor pueda reajustar el tamaño de sus paquetes correspondientemente.

El MTU minimo para IPv6 es 1200. El MTU minimo para IPv4 es 68. Por lo tanto, Jool puede encontrarse queriendo reportar un MTU illegal mientras esta traduciendo un _Fragmentation Needed_ (v4) en un _Packet too Big_ (v6).

- Si `--boostMTU` esta en ON, el único MTU IPv6 que Jool reportará es 1200.
- Si `--boostMTU` está en OFF, Jool no tratará de modificar MTUs.


En realidad, Jool aun tiene que modificar los valores MTU para tener en cuenta la diferencia entre la longitud básica del header IPv4(20) y la del header IPv6(40). Un paquete IPv6 puede ser 20 bytes mas grande que el MTU IPv4 por que va a perder 20 bytes cuando su cabecera IPv6 sea reemplazada por una IPv4.


Aquí está el algoritmo completo:

		IPv6_error.MTU = IPv4_error.MTU + 20
		if --boostMTU == true AND IPv6_error.MTU < 1280
			IPv6_error.MTU = 1280

La [sección 6 del RFC 6145](http://tools.ietf.org/html/rfc6145#section-6) describe los fundamentos básicos.

Toma en cuenta que, si `--setDF` y `--boostMTU`estan ambos en ON y hay un enlace IPv4 con MTU < 1260, tienes un bucle infinito similar al [MTu hassle](esp-misc-mtu.html):

1. El emisor IPv6 transmite un paquete de tamaño 1280.
2. Jool lo traduce en un paquete IPv4 de tamaño 1260 con DF=1
3. Un router IPv4 con interfaz de salida con MTU < 1260 genera _ICMPv6 Frag Needed_ con MTU=1000 (o lo que sea).
4. Jool lo traduce a ICMPv6 _Packet Too Big_ con MTU=1280.
5. Ve al punto 1.

Extendemos un agradecimiento a Tore Anderson por darse cuenta de (y sobre todo por escribir) acerca de esta peculiaridad. 