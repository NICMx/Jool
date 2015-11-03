---
language: es
layout: default
category: Documentation
title: --plateaus
---

[Documentación](documentation.html) > [Aplicación de Espacio de Usuario](documentation.html#aplicacin-de-espacio-de-usuario) > `--plateaus`

# MTU Plateaus (Ejemplo)

## Introducción

Este artículo explica el propósito del parámetro `--plateaus` mediante un ejemplo.

Esta es la red que se va a utilizar:

![Fig.1 - Red](../images/plateaus-network.svg)

El número máximo de bytes por paquete (MTU) de los enlaces _n6-J_ y _J-r4_ es 1500.

El enlace _r4-n4_ es una red ARPANET, y por lo tanto, [sus paquetes pueden medir hasta 8159 bits](https://en.wikipedia.org/wiki/BBN_Report_1822) (~1007 bytes).

Las cabeceras de IPv4 son 20 bytes más pequeñas que las de IPv6 y existen otras peculiaridades, pero para propósitos de facilitar la comprensión, el ejemplo pretenderá que Jool no modificará el tamaño de los paquetes que traduce.

## Ejemplo

_n6_ quiere enviar un paquete IPv6 de 1500 bytes a _n4_ (100 bytes de header y 1400 bytes de datos). _J_ lo convierte a un paquete IPv4 de 1500 bytes y lo envía a _r4_. _r4_ no puede transmitirlo a _n4_ porque es demasiado grande para el límite establecido de 1007 bytes, de modo que devuelve un error de ICMP a _n6_.

![Fig.2 - Intento 1](../images/plateaus-attempt1.svg)

La técnica [Path MTU discovery](http://en.wikipedia.org/wiki/Path_MTU_Discovery) opera bajo la suposición de que el router que no puede entregar el paquete reportará el tamaño máximo de paquete que puede transmitir. En este punto, el error ICMP contendría el número mágico "1007", y entonces _n6_ sabría que tiene que segmentar su paquete acordemente si sigue interesado en la llegada de su mensaje.

Desafortunadamente, la especificación del protocolo ICMPv4 no ordena la inclusión del número; esto se definió después. Si _r4_ es lo suficientemente antiguo, dejará el campo MTU sin asignar (cero), y _n6_ no conocerá el tamaño ideal de su paquete (ICMPv6 ordena la inclusión del dato, de modo que _n6_ depende de él).

Solamente el NAT64 sabe lo que está pasando, de modo que en él recae la tarea de solucionar el problema.

_J_ se dará cuenta de que existe un problema al tratar de traducir un error ICMPv4 con MTU cero. _J_ no tiene una forma de saber el MTU de la red _r4-n4_, de modo que tiene que adivinar. Sabiendo que el paquete rechazado medía 1500 bytes, escoge el plateau más cercano que lo rechazaría:

	   Plateau    MTU    Comments                      Reference
	   ------     ---    --------                      ---------
		      65535  Official maximum MTU          RFC 791
		      65535  Hyperchannel                  RFC 1044
	   65535
	   32000             Just in case
		      17914  16Mb IBM Token Ring
	   17914
		      8166   IEEE 802.4                    RFC 1042
	   8166
		      4464   IEEE 802.5 (4Mb max)          RFC 1042
		      4352   FDDI (Revised)                RFC 1188
	   4352 (1%)
		      2048   Wideband Network              RFC 907
		      2002   IEEE 802.5 (4Mb recommended)  RFC 1042
	   2002 (2%)
		      1536   Exp. Ethernet Nets            RFC 895
		      1500   Ethernet Networks             RFC 894
		      1500   Point-to-Point (default)      RFC 1134
		      1492   IEEE 802.3                    RFC 1042
	   1492 (3%)
		      1006   SLIP                          RFC 1055
		      1006   ARPANET                       BBN 1822
	   1006
		      576    X.25 Networks                 RFC 877
		      544    DEC IP Portal
		      512    NETBIOS                       RFC 1088
		      508    IEEE 802/Source-Rt Bridge     RFC 1042
		      508    ARCNET                        RFC 1051
	   508 (13%)
		      296    Point-to-Point (low delay)    RFC 1144
	   296
	   68                Official minimum MTU          RFC 791
       

_J_ sospecha que la red _r4-n4_ es una IEEE 802.3 y, por tanto, traduce el error ICMPv4 con MTU cero a un error ICMPv6 con MTU 1492.

_n6_ segmenta su mensaje y envía dos paquetes: Uno de longitud 1492 (100 bytes de cabecera y 1392 de datos), y otro de 108 bytes (100 de cabecera y 8 de datos). después de que _J_ traduce, _r4_ rechaza nuevamente porque el primer paquete sigue sin encajar en un máximo de 1007 bytes.

![Fig.3 - Intento 2](../images/plateaus-attempt2.svg)

_J_ sigue el mismo procedimiento: Al ver que está tratando de traducir un error ICMP con MTU 0, busca el plateau más cercano que rechazaría el paquete. Dado que el paquete mide 1492 bytes esta vez, _J_ elige correctamente el MTU 1006.

Esta vez, n6 segmenta sus datos en un paquete de tamaño 1006 (100 + 906) y otro de 594 (100 + 494). Una vez traducidos, estos paquetes encajan y llegan a _n4_.

![Fig.4 - Intento 3](../images/plateaus-attempt3.svg)

## Recapitulando

Plateaus es una buena estrategia para descubrir el MTU de un camino. Dado que toma como referencia MTUs existentes conocidos, es capaz de converger rápido y optimizar la segmentación de la información. Para más detalles, ver [la sección 5 del RFC 1191](http://tools.ietf.org/html/rfc1191#section-5).

Por otra parte, el lector podría observar que la lista carga MTUs obsoletos (como es el caso de ARPANET). El RFC 1191 recomienda que implementadores usen referencias actualizadas para escoger un conjunto de plateaus, pero estas no parecen existir.

No es un problema grave, dado que varios protocolos de la tabla siguen en uso, y que tener demasiados plateaus es mejor que tener insuficientes.

Y cabe mencionar Jool no tiene la lista de plateaus escrita en piedra. El siguiente comando puede usarse para reemplazarla:

	$(jool) --mtu-plateaus <list>

Por ejemplo:

	jool_siit --mtu-plateaus "80000, 40000, 20000, 10000"
