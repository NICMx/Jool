---
layout: documentation
title: Documentación - Parámetros > MTU Plateaus
---

[Documentation](esp-doc-index.html) > [Aplicación de espacio de usuario](esp-doc-index.html#aplicacin-de-espacio-de-usuario) > [Parámetros](esp-usr-flags.html) > [\--global](esp-usr-flags-global.html) > \--plateaus

# MTU Plateaus (Ejemplo)

## Introducción

Este articulo explica el propósito de el parametro `--plateaus` mediante un ejemplo.


Esta es la red de ejemplo:

![Fig.1 - Red](images/plateaus-network.svg)

El numero máximo de bytes por paquete (MTU) de los enlaces _n6-J_ y _J-r4_ es 1500.

El enlace _r4-n4_ es una red ARPANET, Por lo tanto, [sus paquetes pueden ser hasta 8159-96 bits de longitud](https://en.wikipedia.org/wiki/BBN_Report_1822)(~1007 bytes).

Para propósitos illustrativos, vamos a pretender que Jool no modificará el tamaño de los paquetes que traduce. En realidad, las cabeceras IPv4 son 20 bytes mas cortas que las cabeceras IPv6, y hay otras peculiaridades tambien, pero son irrelevantes para los propositos de este ejemplo.

Aqui va:

## Ejemplo

_n6_ quiere escribir un paquete IPv6 de 1500 bytes a _n4_ (piensa en 100 bytes de headers y 1400 bytes de datos útiles). _J_ lo convierte a un paquete IPv4 de 1500 bytes y lo envía a _r4_. _r4_ no puede redireccionarlo por que es muy grande para el limite de 1007 bytes de la red _r4-n4_, asi que devuelve un error ICMP a _n6_.

![Fig.2 - Intento 1](images/plateaus-attempt1.svg)

La técnica [Path MTU discovery](http://en.wikipedia.org/wiki/Path_MTU_Discovery) opera bajo la suposición de que el router que no puede redireccionar el paquete reportará el tamaño máximo de paquete que puede transmitir. En este punto, el error ICMP contendria el número mágico "1007", y entonces _n6_ sabría que tiene que segmentar su paquete en las piezas necesarias si es que sigue interesado en la llegada de su mensaje.

Desafortunadamente, la especificación ICMPv4 no ordena la inclusión del numero; es una idea tardía. Si _r4_ es lo suficientemente antiguo, dejará el campo MTU sin asignar(esto es. cero), y _n6_ sera desconcertado ante la perspectiva de tener que dividir sus datos en grupos de zero bytes cada uno (ICMPv6 ordena la unclusión del campo MTU, así que los nodos confían en el).

Siendo el único que tiene comprensión sobre cual es el problema, la tarea de encontrar una forma de solucionar esto recae en el NAT64.

_J_ se dará cuenta de que el problema existe por que observará que está tratando de traducir un error ICMPv4 con MTU cero a ICMPv6, donde eso es illegal. _J_ no tiene una forma de saber el MTU de la red _r4-n4_, así que tiene que adivinar. Sabe que el paquete rechazado fue de 1500 bytes de longitud, asi que va y pega un vistazo al parámetro `--plateaus`, cuyo valor default está basado en la siguiente tabla, y escoge el primer plateau el cual rechazaria un paquete con tamaño de 1500:

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
       

Asi que _J_ sospecha que la red _r4-n4_ es una IEEE 802.3. Traduce el error ICMPv4 con MTU de valor cero a un error ICMPv6 con MTU de valor 1492.

_n6_ segmenta su mensaje y ahora trata se enviar uno de 1492 de longitud (100 bytes de cabeceras y 1392 de datos útiles), y un paquete de 108 bytes(100 de cabecera, y 8 de datos útiles). _J_ lo traduce, y luego otra vez _r4_ dice "solicitud rechazada" (por que un paquete de 1492 bytes sigue sin encajar en una red con un MTU de 1007).

![Fig.3 - Intento 2](images/plateaus-attempt2.svg)

_J_ otra vez se da cuenta de que esta tratando de traducir un error ICMP de MTU 0, asi que otra vez intenta reportar el primer plateau el cual objetaría al paquete rechazado. Esta vez, el siguiente plateau de 1492 is 1006, asi que _J_ supone que _r4-n4_ es una SLIP o ARPANET. Como puedes ver, esta vez la suposición es correcta.

Al recibir la noticia, n6 ahora segmenta sus datos en un paquete de tamaño 1006 (100 + 986) y uno de 594 (100 + 494). Esta vez, las versiones traducidas encajan y llegan a su destino.


![Fig.4 - Intento 3](images/plateaus-attempt3.svg)

## Envolviendo

La estrategia plateaus es la mejor alternativa de muchos enfoques de **Path MTU Discovery**. Por que esta consciente de MTUs existentes, converge rapido y deja poco espacio para la sub-utilización (ve la [Sección 5 del RFC 1191](http://tools.ietf.org/html/rfc1191#section-5")).

Por otra parte, .Solo mirando el ejemplo puedes haber pensado "ARPANET se disolvió hace mucho tiempo!", y estarías en lo correcto. Aunque el RFC 1191 dice "los implementadores deben usar referencias actualizadas para escoger un conjunto de plateaus", niguna parece surgir.

No es tan malo, dado que algunos de los protocolos en la tabla todavia siguen en uso, y teniendo unos cuantos plateaus redundantes es mejor que tener algunos faltantes.

Y eso no significa que la lista plateaus esta codificada directamente en Jool, tampoco. Si quieres cambiar tu lista plateaus, ejecuta (despues de instalar la [Aplicación de espacio de usuario](esp-usr-install.html).

	$(jool) --mtu-plateaus <list>

Por ejemplo:

	jool_siit --mtu-plateaus "80000, 40000, 20000, 10000"
