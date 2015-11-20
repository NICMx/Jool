---
language: es
layout: default
category: Documentation
title: 464XLAT
---

[Documentación](documentation.html) > [Arquitecturas definidas](documentation.html#arquitecturas-definidas) > 464XLAT

# 464XLAT

## Índice

1. [Introducción](#introduccin)
2. [Red de ejemplo](#red-de-ejemplo)
3. [Flujo de paquetes esperado](#flujo-de-paquetes-esperado)
4. [Pruebas](#pruebas)
5. [Palabras de cierre](#palabras-de-cierre)
6. [Lecturas adicionales](#lecturas-adicionales)

## Introducción

Este documento es un resumen de la arquitectura 464XLAT ([RFC 6877](https://tools.ietf.org/html/rfc6877)), colapsado en un tutorial que utiliza a Jool.

## Planteamiento del problema

Dejando de lado al [RFC 6384](https://tools.ietf.org/html/rfc6384), NAT64 solamente traduce cabeceras de red (IPv4, IPv6 y ICMP) y de transporte (UDP y TCP). Desafortunadamente, algunos protocolos que trabajan encima de UDP y TCP tienen el mal hábito de incluir direcciones IP ("literales IP") a lo largo de sus conversaciones. Dado que NAT64 solo traduce protocolos de capas inferiores, estos valores pasarán por el NAT64 sin ser traducidos.

Por ejemplo, esto es HTML sano:
 
	<a href="www.jool.mx/index.html">Enlace a algo.</a>
 
Esto no:

	<a href="203.0.113.24/index.html">Enlace a algo.</a>

Esta dirección está dentro del cuerpo de un archivo HTML, no de una cabecera de transporte de red. No es viable que Jool soporte traducción de todos los protocolos de aplicación existentes.

Acceder a la segunda versión del enlace desde un nodo que solamente tiene direcciones IPv6 no funciona porque el nodo no tiene un stack de IPv4 con el cual acceder a 203.0.113.24. "www.jool.mx" funciona correctamente porque el DNS64 adjunta el prefijo de pool6 cuando el nodo pregunta por el dominio; si todo lo que el nodo tiene es "203.0.113.24", no puede saber que puede hacer su petición a través de un NAT64, y menos adivinar el prefijo que necesita añadir.

[464XLAT](https://tools.ietf.org/html/rfc6877) es una técnica que soluciona esta limitante. Funciona agregando un SIIT "espejo" a la ecuación, que revierte el trabajo hecho por el Stateful NAT64. Esto le da un stack IPv4 a un número limitado de clientes IPv6 con el cual pueden interactuar con literales.

## Red de ejemplo

![Figura 1 - 464 se necesita](../images/network/464-needed.svg)

Este es probablemente la situación típica. La caja roja es una red sobre la cual tenemos control. El ISP provee solamente direcciones IPv6, pero también acceso a IPv4 mediante un Stateful NAT64 (_PLAT_; "Traductor del proveedor"). _n4_ es un nodo de Internet IPv4 aleatorio.

El usuario de _n6_ hace click a un enlace hacia `203.0.113.24`. _n6_ no tiene una pila IPv4, de modo que la solicitud no tiene a donde ir. La situación puede ser enmendada agregando el prefijo de _PLAT_ a la direccion, pero el usuario no lo sabe. Por supuesto, un DNS64 seria la solución ideal y transparente, pero desafortunadamente el sitio proporcionó una dirección y no un nombre de dominio, de modo que _n6_ no está consultando al DNS.

En términos amplios, la solución es proporcionar a _n6_ una pila IPv4 "falsa" cuyos paquetes serán traducidos a IPv6 antes de llegar al _PLAT_. En otras palabras, un servicio SIIT (en terminos 464XLAT llamado _CLAT_; "Traductor del cliente") estará, de cierta forma, deshaciendo el trabajo del _PLAT_.

Si _n6_ es un caso aislado y se desea aislar el hack espejo lo más posible, [_n6_ puede ser su propio CLAT](node-based-translation.html). Por otro lado, si se desea proveer este servicio a varios nodos, _R_ es un mejor candidato:

![Figure 2 - Red 464XLATada](../images/network/464-network.svg)

También se removieron las nubes del diagrama para simplificar enrutamiento en el ejemplo. La idea de traducción dual no tiene nada que ver con ruteo, de modo que esto no es importante.

## Flujo de paquetes esperado

Este es el flujo normal que un paquete IPv6 atravesaría. Es un flujo Stateful NAT64 típico y la traducción dual presentada en esta configuración no interferirá con él. Nótese que se ha elegido 64:ff9b::/96 como [pool6](usr-flags-pool6.html) del _PLAT_:

![Figura 3 - Flujo normal](../images/flow/464-normal-es.svg)

El flujo 464XLAT que se desea lograr es el siguiente. _n6_ utilizará su dirección IPv4 para consultar el valor literal (o cualquier dirección de internet IPv4):

![Figura 4 - Literal](../images/flow/464-literal-es.svg)

_R_ va a "SIITear" el paquete para que atraviese el pedazo IPv6. La dirección 192.168.0.8 va a ser traducida con la EAMT, y 203.0.113.24 mediante el `pool6` de _PLAT_.

![Figura 5 - Paquete "SIITeado"](../images/flow/464-sless-es.svg)

_PLAT_ hará su magia y mandará el paquete a la Internet IPv4:

![Figura 6 - Paquete "NAT64ado"](../images/flow/464-sful-es.svg)

Y el baile será invertido para la respuesta:

![Figura 7 - Mirror](../images/flow/464-mirror-es.svg)

## Configuración

_n6_ no sabe que de alguna forma es dueño de otra dirección IPv6 en la red 2001:db8:2::/96. Nunca ve este tráfico porque _R_ siempre siempre lo traduce hacia 192.0.2.0/24.

	service network-manager stop

	ip link set eth0 up
	ip addr add 2001:db8:1::8/64 dev eth0
	ip addr add 192.168.0.8/24 dev eth0

	ip route add default via 2001:db8:1::1
	ip route add default via 192.168.0.1

Esto es _R_:

	service network-manager stop

	ip link set eth0 up
	ip addr add 192.168.0.1/24 dev eth0
	ip addr add 2001:db8:1::1/64 dev eth0

	ip link set eth1 up
	ip addr add 2001:db8:100::1/64 dev eth1

	# El tráfico dirigido hacia el Internet IPv4 real va a través de PLAT.
	ip route add 64:ff9b::/96 via 2001:db8:100::2

	# Habilitar enrutamiento.
	sysctl -w net.ipv6.conf.all.forwarding=1
	sysctl -w net.ipv4.conf.all.forwarding=1

	# Habiilitar SIIT.
	# Estamos enmascarando la red privada usando una entrada EAMT.
	# Tráfico hacia el Internet va a concatenarse al prefijo de PLAT.
	modprobe jool_siit pool6=64:ff9b::/96
	jool_siit --eamt --add 192.168.0.8/29 2001:db8:2::/125

El paquete de _n6_ tendrá la dirección `192.168.0.8` y `203.0.113.24`. La primera será traducida utilizando el registro EAMT (ya que coincide con `192.168.0.8/29`) y la segunda mediante el prefijo `pool6` (porque no coincide con la entrada EAM).

Este es _PLAT_:

	service network-manager stop

	ip link set eth0 up
	ip addr add 2001:db8:100::2/64 dev eth0
	# Estoy asumiendo que el ISP nos facilitó estos dos prefijos.
	ip route add 2001:db8:1::/64 via 2001:db8:100::1
	ip route add 2001:db8:2::/64 via 2001:db8:100::1

	ip link set eth1 up
	ip addr add 203.0.113.1/24 dev eth1
	ip addr add 203.0.113.2/24 dev eth1

	modprobe jool pool6=64:ff9b::/96 pool4=203.0.113.2

Y _n4_ es perfectamente aburrido:

	service network-manager stop

	ip link set eth0 up
	ip addr add 203.0.113.24/24 dev eth0
	ip route add default via 203.0.113.2

## Pruebas

Ping de _n6_ hacia _n4_ mediante IPv4:

	$ ping 203.0.113.24 -c 1
	PING 203.0.113.24 (203.0.113.24) 56(84) bytes of data.
	64 bytes from 203.0.113.24: icmp_seq=1 ttl=62 time=4.13 ms

	--- 203.0.113.24 ping statistics ---
	1 packets transmitted, 1 received, 0% packet loss, time 0ms
	rtt min/avg/max/mdev = 4.130/4.130/4.130/0.000 ms

- [ipv4-n6.pcapng](../obj/464xlat/ipv4-n6.pcapng)
- [ipv4-r.pcapng](../obj/464xlat/ipv4-r.pcapng)
- [ipv4-plat.pcapng](../obj/464xlat/ipv4-plat.pcapng)
- [ipv4-n4.pcapng](../obj/464xlat/ipv4-n4.pcapng)

Ping de _n6_ hacia _n4_ mediante IPv6:

	$ ping6 64:ff9b::203.0.113.24 -c 1
	PING 64:ff9b::203.0.113.24(64:ff9b::cb00:7118) 56 data bytes
	64 bytes from 64:ff9b::cb00:7118: icmp_seq=1 ttl=62 time=14.0 ms

	--- 64:ff9b::203.0.113.24 ping statistics ---
	1 packets transmitted, 1 received, 0% packet loss, time 0ms
	rtt min/avg/max/mdev = 14.053/14.053/14.053/0.000 ms

- [ipv6-n6.pcapng](../obj/464xlat/ipv6-n6.pcapng)
- [ipv6-r.pcapng](../obj/464xlat/ipv6-r.pcapng)
- [ipv6-plat.pcapng](../obj/464xlat/ipv6-plat.pcapng)
- [ipv6-n4.pcapng](../obj/464xlat/ipv6-n4.pcapng)

## Palabras de cierre

Aunque 464XLAT provee defensas contra literales IP, existe al menos un [protocolo de aplicación](http://tools.ietf.org/html/rfc959) tan pobremente diseñado que trabaja diferente dependiendo de si está trabajando sobre IPv6 o IPv4. Como resultado, [464XLAT por sí solo no es suficiente para hacerlo funcionar](https://github.com/NICMx/NAT64/issues/114).

Por otra parte, algunos protocolos solo dependen parcialmente de valores literales, y el NAT64 no va a entrometerse cuando no los usen. El modo "pasivo extendido" de FTP cae en esta categoria.

Aquí hay una lista de protocolos que se sabe que usan literales. El [RFC 6586](http://tools.ietf.org/html/rfc6586) también puede ser de interés.

 - FTP (Modos activo y pasivo)
 - Skype
 - NFS
 - Google Talk Client
 - AIM (AOL)
 - ICQ (AOL)
 - MSN
 - Webex
 - [Algunos juegos](http://tools.ietf.org/html/rfc6586#section-5.4)
 - [Spotify](http://tools.ietf.org/html/rfc6586#section-5.5)
 - [HTML pobremente codificado](http://tools.ietf.org/html/rfc6586#section-6.1)

