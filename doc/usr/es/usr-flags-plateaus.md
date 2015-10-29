---
language: es
layout: default
category: Documentation
title: --plateaus
---

[Documentation](documentation.html) > [Aplicación de espacio de usuario](documentation.html#aplicacin-de-espacio-de-usuario) > [Parámetros](usr-flags.html) > [\--global](usr-flags-global.html) > \--plateaus

# MTU Plateaus (Ejemplo)

## Introducción

Este articulo explica el propósito del parametro `--plateaus` mediante un ejemplo.


Esta es la red de ejemplo:

![Fig.1 - Red](../images/plateaus-network.svg)

El número máximo de bytes por paquete (MTU) de los enlaces _n6-J_ y _J-r4_ es 1500.

El enlace _r4-n4_ es una red ARPANET, Por lo tanto, [sus paquetes pueden ser de 96-8159 bits de longitud](https://en.wikipedia.org/wiki/BBN_Report_1822) (~1007 bytes).

Aunque las cabeceras de IPv4 son 20 bytes más cortas que las de IPv6 y existen otras peculiaridades; para propósitos de facilitar la comprensión, vamos a establecer que Jool no modificará el tamaño de los paquetes que traduce. 

## Ejemplo

_n6_ quiere enviar un paquete IPv6 de 1500 bytes a _n4_ (100 bytes de header y 1400 bytes de datos). _J_ lo convierte a un paquete IPv4 de 1500 bytes y lo envía a _r4_. _r4_ no puede retransmitirlo a _n4_ por que es muy grande para su límite establecido de 1007 bytes, asi que devuelve un error de ICMP a _n6_.

![Fig.2 - Intento 1](../images/plateaus-attempt1.svg)

La técnica [Path MTU discovery](http://en.wikipedia.org/wiki/Path_MTU_Discovery) opera bajo la suposición de que el router que no puede entregar el paquete reportará el tamaño máximo de paquete que puede transmitir. En este punto, el error ICMP contendria el número mágico "1007", y entonces _n6_ sabría que tiene que segmentar su paquete en las piezas necesarias si es que sigue interesado en la llegada de su mensaje.

Desafortunadamente, la especificación del protocolo de ICMPv4 no ordena la inclusión del número; esto es una idea tardía. Si _r4_ es lo suficientemente antiguo, dejará el campo MTU sin asignar(esto es cero), y _n6_ sería confundido ante la perspectiva de tener que dividir sus datos en grupos de cero bytes. ICMPv6 ordena la inclusión del campo MTU, así que los nodos dependen en ello.

La tarea de encontrar una forma de solucionar esto recae en el NAT64 dado que es el único que tiene comprensión sobre cuál es el problema.

_J_ se dará cuenta de que existe un problema por que observará que está tratando de traducir un error ICMPv4 con MTU cero a ICMPv6, donde eso es illegal. _J_ no tiene una forma de saber el MTU de la red _r4-n4_, así que tiene que adivinar. Sabe que el paquete rechazado fue de 1500 bytes de longitud, asi que revisa el parámetro `--plateaus`, cuyo valor por omisión está basado en la siguiente tabla [ver RFC. 1191](https://tools.ietf.org/html/rfc1191#section-7.1), y escoge el plateau más cercano inferior que rechazaría un paquete con tamaño de 1500:

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
       

Asi que _J_ sospecha que la red _r4-n4_ es un paquete con formato IEEE 802.3, y por tanto, traduce el error ICMPv4 con MTU de valor cero a un error ICMPv6 con MTU de valor 1492.

_n6_ segmenta su mensaje y ahora envia dos paquetes, uno de 1492 de longitud (100 bytes de cabecera y 1392 de datos), y otro de 108 bytes(100 de cabecera, y 8 de datos). _J_ los traduce, y luego otra vez _r4_ dice "solicitud rechazada", por que el primer paquete de 1492 bytes sigue sin encajar en una red con un MTU de 1007.

![Fig.3 - Intento 2](../images/plateaus-attempt2.svg)

_J_ otra vez se da cuenta de que esta tratando de traducir un error ICMP con MTU 0, asi que otra vez reportar el primer plateau el cual objetaría al paquete rechazado. Esta vez, el siguiente plateau de 1492 is 1006, asi que _J_ supone que _r4-n4_ es un paquete SLIP o ARPANET. Como puedes ver, esta vez la suposición es correcta.

Al recibir la noticia, n6 ahora segmenta sus datos en un paquete de tamaño 1006 (100 + 906) y otro de 594 (100 + 494). Esta vez, los paquetes traducidos de IPv6 cumplen con el requerimiento de longitud establecida por _r4_ y llegan a _n4_.


![Fig.4 - Intento 3](../images/plateaus-attempt3.svg)

## Recapitulando

La estrategia plateaus es la mejor alternativa existente para efecutar un **Path MTU Discovery**. Por que toma como referencia los MTUs existentes, converge rápido y no permite la fragmentación excesiva del paquete. Para una compresión más profunda sobre el _PMTU Discovery_ [vea el RFC 1191](http://tools.ietf.org/html/rfc1191").

Por otra parte, mirando el ejemplo podrías haber pensado "ARPANET se disolvió hace mucho tiempo!", y estarías en lo correcto. Aunque el RFC 1191 dice "los implementadores deben usar referencias actualizadas para escoger un conjunto de plateaus", nadie ha propuesto algo.

Consideramos que no es tan negativo usar la lista tal cual, dado que algunos de los protocolos de la tabla todavía siguen en uso. Es más precavido, conservar todos los valores  versus a que nos lleguen a faltar.

Cabe mencionar que la lista plateaus NO está codificada directamente en Jool. Si deseas establecer tu propia lista plateaus, ejecuta (después de instalar la [Herramienta de configuración de Jool](install-usr.html).

	$(jool) --mtu-plateaus <list>

Por ejemplo:

	jool_siit --mtu-plateaus "80000, 40000, 20000, 10000"
