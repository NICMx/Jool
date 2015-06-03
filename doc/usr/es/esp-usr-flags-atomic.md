
---
layout: documentation
title: Documentación - Flags > Fragmentos Atómicos
---

[Documentation](esp-doc-index.html) > [Herramienta de configuración de Jool](esp-doc-index.html#Aplicacion-de-espacio-de-usuario) > [Flags](esp-usr-flags.html) > [\--global](esp-usr-flags-global.html) > Fragmentos Atómicos

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

Los "Fragmenos Atómicos" son por decirlo de otra manera "fragmentos aislados"; es decir, son paquetes de IPv6 que poseen un _Fragment Header_ sin que éste realmente sea un trozo de un paquete mayor. Este tráfico de fragmentos es permitido entre los saltos, _hops_, para el envío de información entre IPv6 e IPv4. Por lo general, estos paquetes son enviados por _hosts_ que han recibido un mensaje de error del tipo ICMPv6 "Packet too Big" para advertir que el próximo equipo, ya sea ruteador, hub, etc., soporta un MTU inferior al mínimo en IPv6, o sea que, el Next-Hop MTU es menor a 1280 bytes. Hay que recordar que entre redes IPv6 el MTU es fijo y es de 1500 bytes; pero en IPv4, el MTU ha variado con el tiempo y depende del medio y del protocolo por el cual se esté comunicando. En IPv6, el nodo origen es quien tiene la obligación de fragmentar el paquete y no los equipos que enlazan la red, cosa que si es permitido en IPv4. Para información sobre las cabeceras de fragmento, [ver RFC. 2460, sección 4.5, 1998](https://tools.ietf.org/html/rfc2460#section-4.5). 

Sin embargo, su implementación es vulnerable a infiltraciones, y algún _hacker_ puede tomar ventaja de la diferencia entre el MTU mínimo de IPv4, que es de 68 bytes, y el de IPv6, que es de 1280, para introducir fragmentos y generar problemas. Algunas referencias son:

[RFC. 5927, 2010](https://tools.ietf.org/html/rfc5927)
[Security Implications of Predictable Fragment Identification Values, 2012] (http://www.si6networks.com/presentations/IETF83/fgont-ietf83-6man-predictable-fragment-id.pdf)
[RFC. 6946, 2013] (https://tools.ietf.org/html/rfc6946). 

La IETF está tratando de normar el [desuso de los fragmentos atómicos](https://tools.ietf.org/html/draft-ietf-6man-deprecate-atomfrag-generation-00). Incluso en el RFC 6145, que es el documento principal de SIIT, advierte sobre dichos [problemas de seguridad](http://tools.ietf.org/html/rfc6145#section-6).

DESDE la perspectiva de Jool, como no se ha oficializado su desuso, estos son soportados.

Pero es destacable mencionar, que se han registrado problemas técnicos para permitir los fragmentos atómicos. El kernel de Linux es particularmente deficiente cuando se trata de cabeceras de fragmento, asi que si Jool está generando uno, Linux añade uno adicional.

[![Figure 1 - que podría salir mal?](images/atomic-double-frag.png)](obj/atomic-double-frag.pcapng)

En Jool 3.2 y en versiones anteriores se evade esto NO delegando la fragmentación al kernel, pero esto nos introdujo otros problemas más sutiles.

Ahora en Jool 3.3, la configuración por omisión es  **deshabilitar** los fragmentos atómicos, lo cual te recomendamos **no** cambies.

Estamos totalmente de acuerdo con la [iniciativa de su desuso, 2014](https://tools.ietf.org/html/draft-ietf-6man-deprecate-atomfrag-generation-00) y en el momento que se formalize, en breve, se omitirán en Jool. 

 y al día de hoy son consideradas **en desuso**. De hecho, intentamos removerlas tan pronto como (y si)[draft-ietf-6man-deprecate-atomfrag-generation](

Que se sepa que aceptamos completamente la deprecación de fragmentos atómicos.

## Parámetros

	Las opciones descritas tienen que ver con fragmentos atómicos

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