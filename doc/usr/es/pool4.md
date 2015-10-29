---
language: es
layout: default
category: Documentation
title: Pool IPv4 Stateful
---

[Documentación](documentation.html) > [Ejemplos de uso](documentation.html#ejemplos-de-uso) > [Stateful NAT64](run-nat64.html) > Pool de direcciones IPv4

# Pool de direcciones IPv4

## Índice

1. [Introducción](#introduccin)
2. [Explicación rápida](#explicacin-rpida)
3. [Explicación elaborada](#explicacin-elaborada)

## Introducción

Este documento sirve como una introducción a `pool4` de NAT64 Jool.

## Explicación rápida

Si estás familiarizado/a con iptables y masquerade, probablemente todo lo que necesitas saber es que

	jool --pool4 --add --tcp 192.0.2.1 5000-6000

Es espiritualmente equivalente a

	ip addr add 192.0.2.1 dev (...)
	iptables -t nat -A POSTROUTING -p TCP -j MASQUERADE --to-ports 5000-6000

## Explicación elaborada

Al igual que NAT, Stateful NAT64 permite a un número indeterminado de clientes compartir un número limitado de direcciones IPv4 distribuyendo estratégicamente su tráfico a través de sus propias direcciones de transporte disponibles.

Llamamos a las "direcciones de transporte disponibles" la "Pool de IPv4" ("pool4" en corto).

Para ilustrar:

![Fig. 1 - petición de n6](../images/flow/pool4-simple1-en.svg "Fig. 1 - petición de n6")

En Jool, escribimos las direcciones de transporte en la forma `<dirección de IPv4>#<puerto>` (en lugar de "`<dirección de IPv4>:<puerto>`"). El paquete mostrado arriba tiene dirección fuente `2001:db8::8`, puerto fuente 5123, dirección destino `64:ff9b::192.0.2.24`, y puerto destino 80.

Asumiendo que pool4 contiene las direcciones `192.0.2.1#5000` hasta la `192.0.2.1#6000`, una posible traducción del paquete es

![Fig. 2 - paquete traducido, versión 1](../images/flow/pool4-simple2-en.svg "Fig. 2 - paquete traducido, versión 1")

Otra, igualmente válida, es

![Fig. 3 - paquete traducido, versión 2](../images/flow/pool4-simple3-en.svg "Fig. 3 - paquete traducido, versión 2")

Los NAT64s no se preocupan por conservar puertos fuente durante traducciones. De hecho, por seguridad, [existen recomendaciones para que tiendan a ser impredecibles]({{ site.draft-nat64-port-allocation }}).

Al definir las direcciones y puertos que van a entrar en pool4, es necesario considerar que no deben colisionar con otros servicios o clientes que puedan estar en el mismo nodo traductor. Si _T_ trata de abrir una coneción desde la dirección de transporte `192.0.2.1#5000`, y a la vez una traducción resulta en la misma dirección de transporte, la información transmitida en las dos conexiones se va a mezclar.

Por defecto, el rango de puertos efímeros en Linux es 32768-61000. Por lo tanto, el rango de puertos en Jool para cualquier dirección es (por defecto) 61001-65535. [Es posible modificar el primero a través del sysctl `sys.net.ipv4.ip_local_port_range`, y el segundo mediante comandos `--pool4 --add` de la aplicación de usuario](usr-flags-pool4.html#notas).

