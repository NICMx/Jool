---
layout: documentation
title: Documentación - RFC 6791
---

[Documentación](esp-doc-index.html) > [Ejemplos de uso](esp-doc-index.html#ejemplos-de-uso) > [SIIT](esp-mod-run-vanilla.html) > RFC 6791

# RFC 6791

## Índice

1. [Introducción](#introduccion)
2. [Definición del Problema](#definicion)
3. [Ejemplo] (#ejemplo)
4. [Notas Adicionales] (#notas-adicionales)

## Introducción

Este estandar fue propuesto en Nov 2011 y aprobado como tal un año después. Presentado por Xing Li y Congxiao Bao del Centro CERNET de la Universidad de Tsinghua y Dan Wing de Cisco.

## Definición del Problema

A stateless IPv4/IPv6 translator may receive ICMPv6 packets containing non-IPv4-translatable addresses as the source.  These packets should be passed across the translator as ICMP packets directed to the IPv4 destination.  This document presents recommendations for source address translation in ICMPv6 headers to handle such cases.

## Ejemplo

Suponga que _n4_ esta tratando de llegar a _n6_, pero hay un problema (ej. el paquete es muy grande), y _R_ envía un error ICMP a _n4_. _T_ está traduciendo usando el prefijo 2001:db8::/96.

![Figura 1 - Red](images/network/rfc6791.svg)

El paquete de _R_ tendrá las siguientes direcciones:

| Origen  | Destino              |
|---------+----------------------|
| 4000::1 | 2001:db8::192.0.2.13 |

_T_ está en problemas por que la dirección de origen del paquete no tiene el prefijo de traducción, asi que no puede ser extraia una dirección IPv4 de el.

Normalmente, no se tienen muchas direcciones IPv4, asi que no es razonable garantizarle una a cada uno de los nodos en el lado IPv6. Debido a su único propósito(casi siempre) de redireccionamiento, los routers son buenos candidatos para direcciones intraducibles. Por otro lado, los errores ICMP son importantes, y un NAT64 no deberia desecharlo simplemente por que viene de un router.

## Notas Adicionales

Por favor considere los siguientes parrafos del [RFC 6791](https://tools.ietf.org/html/rfc6791) mientras decide el tamaño y las direcciones de su RFC 6791 pool:

	La dirección de origen utilizada NO DEBE causar que le paquete ICMP
	sea descartado. NO DEBE ser tomada del espacio de direcciones de
    [RFC1918] o de [RFC6598], ya que ese espacio de direcciones es probable
    a estar sujeto al filtrado unicast Reverse Path Forwarding (uRPF) [RFC3704].

	(...)

	Otra consideración para la seleccion del origen es que debe ser
	posible para los contenedores IPv4 del mensaje ICMP ser capaces de
	distinguir entre la diferentes posibles fuentes de los mensajes ICMPv6
	(por ejemplo, soportar una herramienta de diagnostico de traza de ruta
	que proporcione algo de visibilidad a nivel d red limitada a través del traductor
    IPv4/Pv6). Esta consideración implica que un traductor IPv4/IPv6
	necesita tener un pool de direcciones IPv4 para mapear la direccion de origen 
    de paquetes ICMPv6 generados desde origenes diferentes, o para incluir
    la información de la dirección de origen IPv6 para mapear la dirección de origen 
	por otros medios.  Actualmente, el TRACEROUTE y el MTR [MTR] son los únicos
	consumidores de mensajes ICMPv6 traducidos que se  translated ICMPv6 messages that care about the
	ICMPv6 source address.
	
	(...)

	Si un pool de direcciones publicas IPv4 está configurado en el traductor,
	Se RECOMIENDA seleccionar aleatoriamente la dirección de origen IPv4 del
	pool. La selección aleatoria reduce la probabilidad de que dos mensajes ICMP
    sucitados por la misma Traza De Ruta puedan especificar la misma dirección
    de origen y, por consiguiente, erroneamente dar la apariencia de un bucle de ruteo.
	

Un Stateful NAT64 generalmente no tiene este problema por que [render every IPv6 address translatable](esp-intro-nat64.html#stateful-nat64) (ya que todos los nodos IPv6 comparten las direcciones IPv4 del NAT64). Para hacer claras las cosas, un modulo SIIT debe de mantener un pool de direcciónes reservadas. Al recibir un error ICMP con un origen que no se puede traducir, Jool deberia asignar un aleatorio de los que contiene en su pool.


El [Ejemplo de SIIT](esp-mod-run-vanilla.html) muestra como configurar el pool durante un modprobe. Tambien lo puedes editar despues mediante la [Aplicación de espacio de usuario](esp-usr-flags-pool6791.html).
