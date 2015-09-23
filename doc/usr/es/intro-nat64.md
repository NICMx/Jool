---
language: es
layout: default
category: Documentation
title: Introducción a los Mecanismos de Transición
---

[Documentación](documentation.html) > [Introducción](documentation.html#introduccin) > Mecanismos de Transición

## Introducción a Traducción IP/ICMP

## Índice

1. [Introducción](#introduccin)
2. [Ejemplos de Traducción](#ejemplos-de-traduccin)<br />
	a) [SIIT con EAM](#siit-con-eam)<br />
    b) [SIIT tradicional](#siit-tradicional)<br />
    c) [Stateful NAT64](#stateful-nat64)
3. [Nota Histórica](#nota-histrica)
    
## Introducción

Este documento proporciona un ejemplo ilustrativo de cada uno de los tres mecanismos de traducción implementados en Jool.
 
## Ejemplos de Traducción
 
SIIT (_Stateless IP/ICMP Translation_) y NAT64 ("NAT seis cuatro", no "NAT sesenta y cuatro") son tecnologías orientadas a comunicar nodos de red que únicamente hablan [IPv4](http://es.wikipedia.org/wiki/IPv4) con nodos que solo hablan [IPv6](http://es.wikipedia.org/wiki/IPv6).

 - **SIIT** modifica paquetes, simplemente reemplazando encabezados de IPv4 por encabezados de IPv6 y viceversa.
 - **Stateful NAT64**, o simplemente NAT64, es una combinación entre un SIIT y un (teórico) NAT de IPv6; la idea es enmascarar cualquier número de nodos de IPv6 detrás de unas pocas direcciones de IPv4.

SIIT solamente comunica nodos. NAT64 requiere más recursos, pero ayuda adicionalmente con el problema del [agotamiento de las direcciones de IPv4](http://es.wikipedia.org/wiki/Agotamiento_de_las_direcciones_IPv4).
 
Por razones históricas, algunas veces etiquetamos erróneamente a SIIT como "Stateless NAT64". Ya que esta expresión no está incluida en ningún estándar relevante, la consideramos imprecisa, a pesar de que tiene cierto grado de sentido. Si es posible, por favor trate de evitarla.
 
### SIIT con EAM


Esta es la modalidad más sencilla de explicar. Considere la siguiente configuración:

![Fig.1 - Red de ejemplo EAM](../images/network/eam.svg "Fig.1 - Red de ejemplo EAM")

(_T_ representa "traductor".)

Asumiendo que la puerta de enlace por default de todos es _T_, comó se podría comunicar _A_ (IPv6) con _V_ (IPv4)?

1. Se le indica a _T_, "La dirección IPv4 de _A_ debe de ser 198.51.100.8, <br />
                   y la dirección IPv6 de _V_ debe de ser 2001:db8:4::16".
2. Se le indica a _A_, "la dirección de _V_ es 2001:db8:4::16".
3. Se le indica a _V_, "la dirección de _A_ es 198.51.100.8 ".

Esto es lo que va a suceder:

![Fig.2 - Flujo EAM](../images/flow/eam-es.svg "Fig.2 - Flujo EAM")

El traductor esta "engañando" a ambos nodos, haciéndoles pensar que el otro puede hablar su mismo protocolo.

"EAM" es abreviación de "Explicit Address Mapping" (Mapeo Explícito de Direcciones), y es más versátil que simples asociaciones entre diferentes direcciones arbitrarias.

![bulb](../images/bulb.png) Más detalles sobre EAM pueden encontrarse en el [borrador]({{ site.draft-siit-eam }}) o [nuestro resumen de él](eamt.html).

### SIIT (tradicional)


El modo básico es más constrictivo. Por lo tanto, es necesario modificar la red:

![Fig.3 - Red de ejemplo Vanilla](../images/network/vanilla.svg "Fig.3 - Red de ejemplo Vanilla")

Para lograr la comunicación entre _A_ y _V_ bastaría con establecer lo siguiente:

- Se le indica a _T_, "Tu prefijo de traducción es 2001:db8::/96".
- Se le indica a _A_, "la dirección de _V_ es 2001:db8::192.0.2.16".
- Se le indica a _V_, "la dirección de _A_ es 198.51.100.8".

La idea es simplemente remover el prefijo de traducción en la dirección IPv6 a IPv4, y adjuntarlo en el otro sentido. Este sería el flujo:

![Fig.4 - Flujo Vanilla](../images/flow/vanilla-es.svg "Fig.4 - Flujo Vanilla")

Por supuesto, esto significa que la dirección IPv4 de cada nodo en IPv6 tiene que ser codificada dentro de su dirección IPv6, lo cual es un poco engorroso.

Podría parecer que "SIIT con EAM" y "SIIT tradicional" son cosas diferentes, pero en realidad son suscriptores de la misma idea básica (mapeo de direcciones 1 a 1). Es posible tener un prefijo de traducción y una EAMT al mismo tiempo; en despliegues de este tipo, el traductor intenta primeramente convertir direcciones consultando la tabla EAM, y si no lo logra, retrocede y usa el prefijo en su lugar.

Puedes encontrar un ejemplo concreto de cómo SIIT "tradicional" y SIIT "EAM" pueden ser combinados para cumplir un caso de uso en [draft-v6ops-siit-dc]({{ site.draft-siit-dc }}).

Dependiendo de la longitud del prefijo, la dirección IPv4 se incorporará en diferentes posiciones dentro de la dirección de IPv6. Puede encontrarse más información en el [RFC 6052](http://tools.ietf.org/html/rfc6052).

![bulb](../images/bulb.png) Siempre que el RFC 6052 esté involucrado, es conveniente dar de alta también un [DNS64](dns64.html) para que los usuarios no necesiten estar al tanto del prefijo, y resuelva por nombre.

### Stateful NAT64


Este modo es más parecido a lo que la gente entiende como **NAT** (_Network Address Translator_). Por lo tanto, es conveniente recordar cómo opera un NAT:

![Fig.5 - Red de ejemplo NAT](../images/network/nat-es.svg "Fig.5 - Red de ejemplo NAT")

Note que la red de la izquierda es llamada "Privada" porque usa [direcciones no disponibles en la Internet Global](http://es.wikipedia.org/wiki/Red_privada). _NAT_ modifica las direcciones de los paquetes para que los nodos externos piensen que el tráfico proveniente de los nodos internos fue en realidad iniciado por él mismo:

![Fig.6 - Flujo NAT](../images/flow/nat-es.svg "Fig.6 - Flujo NAT")

Desde el punto de vista del operador, los nodos _A_, _B_, _C_, _D_, _E_ y _NAT_ están "compartiendo" la(s) dirección(es) global(es) de _NAT_.

NAT ayuda a reducir el empleo de direcciones globales en Internet de IPv4, pero tiene un precio: _NAT_ es **stateful**; tiene que recordar por cierto tiempo qué nodo privado emitió el paquete a _V_, porque la dirección de _A_ fue completamente borrada durante el enmascarado. Si _NAT_ se olvida de _A_, no tiene cómo saber a quién va dirigida la respuesta de _V_.

Dos cosas que hay que tomar en cuenta es:

- Cada mapeo require memoria.
- _V_ no puede **iniciar** la comunicación con _A_, porque primeramente el _NAT_ **debe** aprender el mapeo en el sentido de la Red_Privada-a-Red_Externa (de izquierda a derecha).

<!--
	Paty: Es mejor no mencionar a NAT-PT por dos razones:
	1. No es un "NAT" (o más bien dicho, no es un "NAT44"); es el precursor de SIIT/NAT64.
	2. Está deprecado (trajo muchos problemas, y por lo tanto salió SIIT/NAT64).
 -->

Si quieres saber más sobre NAT, consulta los RFCs [2663](https://tools.ietf.org/html/rfc2663#section-3) y [3022](https://tools.ietf.org/html/rfc3022).

**Stateful NAT64** es muy similar a NAT. Conceptualmente, la única diferencia es que la "Red Privada" es de hecho una red (pública) de IPv6:

![Fig.7 - Red de ejemplo Stateful NAT64](../images/network/stateful.svg "Fig.7 - Red de ejemplo Stateful NAT64")

Para lograr la comunicación entre _A_ y _V_ bastaría con establecer lo siguiente:

- Se le indica a _A_, "la dirección de _V_ es 2001:db8::203.0.113.16".
- A _V_ no se le indica nada; él cree que está hablando con _T_.
- Se le indica a _T_, "Usa tu dirección para enmascarar a _A_".

La idea es reemplazar la dirección de _A_ y remover el prefijo a _V_ durante la traducción de IPv6 a IPv4, y adjuntar el prefijo en _V_ y quitar la máscara en el sentido contrario.

![Fig.8 - Flujo Stateful](../images/flow/stateful-es.svg "Fig.8 - Flujo Stateful")

El punto de NAT64 es que los nodos de IPv6 no se ocultan detrás de un único gateway hacia IPv4; por el contrario, _T_ solamente desemboca hacia la "subred" que es el Internet de IPv4. El Internet de IPv6 es alcanzable desde otro gateway:

![Fig.9 - Internet Stateful NAT64](../images/network/full-es.svg "Fig.9 - Internet Stateful NAT64")

De esta manera, los nodos _A_ hasta _E_ son solo de _IPv6_, pero tienen acceso a ambas Internets. A la IPv6 mediante un ruteador _R_, y a la IPv4 mediante _T_.

Si gustas conocer el resto de los **escenarios posibles en Stateful NAT64 y SIIT** consulta el [RFC 6144, cap. 2](https://tools.ietf.org/html/rfc6144#section-2).

![warning](../images/warning.png) Para soportar direccionamiento por nombre se requiere habilitar el [DNS64](dns64.html).

## Nota Histórica

Sobre el orígen y desarrollo de estas metodologías:

* El algoritmo para SIIT fue definido formalmente a inicios del 2000 por Erik Nordmark de SUN Microsystems en el [RFC 2765](https://tools.ietf.org/html/rfc2765). Este ha sido actualizado en varias ocasiones: [(RFC 6145, 2011)](https://tools.ietf.org/html/rfc6145), [(RFC6791, 2012)](https://tools.ietf.org/html/rfc6791) e inclusive [hasta nuestros días](https://tools.ietf.org/id/siit?maxhits=100&key=date&dir=desc). De éstos, ya están incluidos en Jool el [(draft-ietf-v6ops-siit-dc, 2015)]({{ site.draft-siit-dc }}), el [(draft-ietf-v6ops-siit-dc-2xlat, 2015)]({{ site.draft-siit-dc-2xlat }}) y el [(draft-anderson-v6ops-siit-eam, 2015)]({{ site.draft-siit-eam }}). Estas tres adiciones a SIIT han sido propuestas y promovidas por [Tore Anderson](http://www.redpill-linpro.com/tore-anderson#overlay-context=about-us/our-consultants) de la compañía Redpill Linpro en Noruega.

* El algoritmo de Stateful NAT64 fue uno de los resultados del [**Proyecto Trilogy**](http://trilogy-project.org/trilogy-and-the-ietf.html), organizado por [la Unión Europea](http://europa.eu/rapid/press-release_IP-11-1294_es.htm), con una inversión aprox. de 9 millones de Euros, por un período de 3 años (2008 al 2010) donde participaron 5 Universidades, 4 compañías de telecomunicación y 2 centros de investigación. El estándar para el NAT64 que es el [RFC 6146](https://tools.ietf.org/html/rfc6146) fue publicado en el 2011 por el mismo coordinador del projecto, el [Dr. Marcelo Bagnulo Braun](http://www.it.uc3m.es/marcelo/) de la Universidad Carlos III y otros dos colaboradores del proyecto. 

![bulb](../images/bulb.png) Conoce más trabajos elaborados por la IETF acerca de NAT64 en [TOOLS IETF](https://tools.ietf.org/id/nat64?maxhits=100&key=date&dir=desc) y en [Datatracker](https://datatracker.ietf.org/doc/search/?name=nat64&sort=&rfcs=on&activedrafts=on).
