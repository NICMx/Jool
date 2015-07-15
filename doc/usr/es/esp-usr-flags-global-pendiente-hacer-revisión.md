---
layout: documentation
title: Documentación - Parámetros > Global
---

[Documentación](esp-doc-index.html) > [Herramienta de configuración de Jool](esp-doc-index.html#aplicacion-de-espacio-de-usuario) > [Parámetros](esp-usr-flags.html) > \--global

# \--global

## Index

1. [Descripción](#descripcion)
2. [Sintaxis](#sintaxis)
3. [Ejemplos](#ejemplos)
4. [Llaves](#keys)
	1. [`--enable` | `--disable`](#enable---disable)
	1. [`--address-dependent-filtering`](#address-dependent-filtering)
	2. [`--drop-icmpv6-info`](#drop-icmpv6-info)
	3. [`--drop-externally-initiated-tcp`](#drop-externally-initiated-tcp)
	4. [`--udp-timeout`](#udp-timeout)
	5. [`--tcp-est-timeout`](#tcp-est-timeout)
	6. [`--tcp-trans-timeout`](#tcp-trans-timeout)
	7. [`--icmp-timeout`](#icmp-timeout)
	8. [`--fragment-arrival-timeout`](#fragment-arrival-timeout)
	8. [`--maximum-simultaneous-opens`](#maximum-simultaneous-opens)
	8. [`--source-icmpv6-errors-better`](#source-icmpv6-errors-better)
	8. [`--logging-bib`](#logging-bib)
	8. [`--logging-session`](#logging-session)
	9. [`--zeroize-traffic-class`](#zeroize-traffic-class)
	10. [`--override-tos`](#override-tos)
	11. [`--tos`](#tos)
	12. [`--allow-atomic-fragments`](#allow-atomic-fragments)
		1. [`--setDF`](#setdf)
		2. [`--genFH`](#genfh)
		3. [`--genID`](#genid)
		4. [`--boostMTU`](#boostmtu)
	13. [`--amend-udp-checksum-zero`](#amend-udp-checksum-zero)
	14. [`--randomize-rfc6791-addresses`](#randomize-rfc6791-addresses)
	13. [`--mtu-plateaus`](#mtu-plateaus)

## Descripción

Bajo esta opción se agrupan todas las variables configurables de Jool exceptuando las tablas (Pool4, Pool6, Pool6791, BIB, Session, EAMT y blacklist), porque cada una de éstas son seleccionables directamente.

`--global` es el modo por omisión de Jool. Asi que de hecho, no requieres ingresar ese parámetro.

## Sintaxis

	jool_siit [--global]
	jool_siit [--global] <llave> <valor>
	jool [--global]
	jool [--global] <llave> <valor>

## Ejemplos

* Para Desplegar la Configuración Actual:

	$ jool_siit --global

O simplemente:

	$ jool_siit

* Para PAUSAR ***Jool***:

	$ jool --global --disable

* Para ENCENDER ***Filtra Dependiendo del Direccionamiento***:

	$ # Valores válidos: {true, false, 1, 0, yes, no, on, off} <br />
	$ jool --address-dependent-filtering true

* Para ACTUALIZAR ***la Lista Plateaus:***

	$ jool_siit --mtu-plateaus "6000, 5000, 4000, 3000, 2000, 1000"

## Llaves

### `--enable`|`--disable`

- Nombre: ***HABILITA & DESHABILITA JOOL***
- Tipo: ***No Aplica***
- Modos: ***SIIT & Stateful***
- Valor por Omisión: ***Depends on modprobe arguments***

REANUDA Y PAUSA LA TRADUCCIÓN DE PAQUETES, RESPECTIVAMENTE. 

Esto puede ser muy útil si requieres cambiar más de un parámetro de configuración y no deseas que los paquetes sean traducidos inconsistentemente mientras ejecutas los comandos; pero, si prefieres que Jool no se detenga mientras estas reconfigurando, usa disable.

Mientras Jool está inactivo, *los timeouts no serán pausados** para que las entradas ya registradas en [BIB](esp-usr-flags-bib.html) y [session](esp-usr-flags-session.html) puedan estarse actualizando y al llegar a su término de duración los [paquetes](maximum-simultaneous-opens) y [fragmentos](#fragment-arrival-timeout) almacenados puedan ser desechados.

### `--address-dependent-filtering`

- Nombre: ***FILTRA DEPENDIENDO DEL DIRECCIONAMIENTO***
- Tipo: ***Booleano***
- Modos: ***Stateful***
- Valor por Omisión: ***APAGADO (0)***
- Nombre anterior: `--dropAddr`
- Fuente: [Ver RFC 6146, sección 1.2.3](http://tools.ietf.org/html/rfc6146#section-1.2.3)

EN RESUMEN:<br />
	--address-dependent-filtering` OFF significa que Jool debe ser un NAT de cono completo.
	--address-dependent-filtering` ON significa que Jool debe ser un NAT de cono restringido.
	
Referencias:<br />
[Wiki](http://en.wikipedia.org/wiki/Network_address_translation#Methods_of_translation).<br />
[Voipex](http://voipex.blogspot.mx/2006/04/que-es-nat-tipos-de-nat-que-es-stun.html).<br />
[Think Like A Computer](http://think-like-a-computer.com/2011/09/16/types-of-nat/).<br />
[voipforo](http://www.voipforo.com/diccionario/N.php).

BREVE EXPLICACIÓN:

Supon que _n6_ está hablando con _n4a_ mediante el NAT64:

![Fig.1: Legal chat](images/usr-dropaddr-1.svg)

El [registro BIB](esp-misc-bib.html) es

| IPv6 transport address | IPv4 transport address | Protocol |
|------------------------|------------------------|----------|
| 2001:db8::1#10         | 192.0.2.1#10           | TCP      |

_n4b_ se da cuenta del servicio de _n6_, quizá por que _n4a_ le dice sobre el:

![Fig.2: n4b finds about n6](images/usr-dropaddr-2.svg)

Luego _n4b_ trata de conversar con _n6_ también:

![Fig.3: suspicious query](images/usr-dropaddr-3.svg)

Ya que el registro BIB existe, _J_ sabe que _n4b_ significa  "2001:db8::1#10" cuando el dice "192.0.2.1#10", asi que el paquete puede ser técnicamente traducido. Sin embargo, debido a las tablas de sesión, _J_ tambien puede decir que _n6_ no ha estado conversando con _n4b_ en el pasado.

Si `--address-dependent-filtering` está deshabilitado, _J_ permitirá al paquete de _n4b_ pasar. Si `--address-dependent-filtering` está encendido, _J_ desechará el paquete de _n4b_ y responderá con un error ICMP con el mensaje "Communication Administratively Prohibited". Esto restringe efectivamente cualquier intento de comunicación iniciado desde IPv4, aún si hay registros BIB (estáticos u otros).

* Si estas utilizando el NAT64 para publicar un servicio que solo soporta IPv6 a la internet IPv4, tiene sentido que `--address-dependent-filtering` esté deshabilitado. Esto es por que se espera que los clientes se enteren del servicio IPv6 por su cuenta, y el servidor de IPv4 normalmente no inicia los flujos de paquetes. 

* Si estás utilizando NAT64 para permitir a los nodos IPv6 navegar en la Internet IPv4, tiene sentido que `--address-dependent-filtering` esté encendido. Dado que los Nodos Clientes de IPv6 eligen sus puertos de manera aleatoria, este mecanismo nos sirve para descartar el acceso a nodos aleatorios externos que pretendan adivinar estos puertos.

`--address-dependent-filtering` Encendido podria impedir metodos de recorrido de NAT como STUN, o por lo menos, hacer imposibles algunos modos de opreación.

### `--drop-icmpv6-info`

- Tipo: ***Booleano***
- Modos: ***Stateful***
- Valor por Omisión: ***APAGADO (0)***

- Nombre anterior: `--dropInfo`
- Fuente: [RFC 6146, section 3.5.3](http://tools.ietf.org/html/rfc6146#section-3.5.3)

Si activas esto, pings (ambas solicitudes y respuestas) serán bloqueados mientras esten siendo traducidos de ICMPv6 a ICMPv4.

Por alguna razón, no se supone que debamos bloquear pings de ICMPv4 a ICMPv6, pero como se necesitan ambas una solicitud y una respuesta para un eco exitoso, el resultado de salida parece ser el mismo.

Esta regla no afectara los mensajes de Error ICMP.


### `--drop-externally-initiated-tcp`

- Tipo: ***Booleano***
- Modos: ***Stateful***
- Valor por Omisión: ***APAGADO (0)***

- Nombre anterior: `--dropTCP`
- Fuente: [RFC 6146, section 3.5.2.2](http://tools.ietf.org/html/rfc6146#section-3.5.2.2)

Enciende `--drop-externally-initiated-tcp` para demoler cualquier intento de iniciar comunicación TCP con nodos IPv6 por parte de nodos IPv4.

Por supuesto, esto **NO** bloqueará el tráfico IPv4 si algun nodo IPv6 lo solicito primero. 

### `--udp-timeout`

- Tipo: ***Entero (segundos)***
- Modos: ***Stateful***
- Valor por Omisión: ***300seg = 5 min***

- Nombre anterior: `--toUDP`
- Fuente: [RFC 6146, section 3.5.1](http://tools.ietf.org/html/rfc6146#section-3.5.1)

Cuando una sesión UDP ha estado inactiva por el periodo de tiempo especificado aqui, su registro será removido de la base de datos automáticamente.

Cuando cambias este valor, los tiempos de vida de todas las sesiones UDP ya existentes seran actualizados.

### `--tcp-est-timeout`

- Tipo: ***Entero (segundos)***
- Modos: ***Stateful***
- Valor por Omisión: ***7200seg = 2 hr***

- Nombre anterior: `--toTCPest`
- Fuente: [RFC 6146, section 3.5.2.2](http://tools.ietf.org/html/rfc6146#section-3.5.2.2)

Cuando una conexión TCP ha permanecido inactiva por el periodo de tiempo especificado aquí, su existencia será cuestionada. Jool enviará un paquete de sondeo a uno de los puntos y eliminará la sesión si una respuesta no es recibida antes de  el `--tcp-trans-timeout` timeout.

Cuando cambias este valor, los tiempos de vida de sesiones TCP ya establecidas son actualizados.


### `--tcp-trans-timeout`

- Tipo: ***Entero (segundos)***
- Modos: ***Stateful***
- Valor por Omisión: ***2400seg = 4 min***

- Nombre anterior: `--toTCPtrans`
- Fuente: [RFC 6146, derivatives of section 3.5.2](http://tools.ietf.org/html/rfc6146#section-3.5.2)

Cuando una sesión TCP insalubre ha estado inactiva durante el periodo de tiempo especificado aquí, su registro será removido de la base de datos automáticamnete. Una seisión "insalubre" es una en la que el handshake TCP no ha sido completado, esta siendo terminada por los puntos, o está técnicamente establecida pero ha permanecido inactica por el tiempo indicado en `--tcp-est-timeout`.

Cuando cambias este valor, los tiempos de vida de sesiones TCP transitorias existentes son actualizados.

### `--icmp-timeout`

- Tipo: ***Entero (segundos)***
- Modos: ***Stateful***
- Valor por Omisión: ***60seg = 1 min***

- Nombre anterior: `--toICMP`
- Fuente: [RFC 6146, section 3.5.3](http://tools.ietf.org/html/rfc6146#section-3.5.3)

Cuando una sesión ICMP ha estado inactiva por el periodo de tiempo especificado aquí, su registro será removida de la base de datos automáticamente.

Cuando cambias este valor, los tiempos de vida de todas las sesiones ICMP son actualizados.

### `--fragment-arrival-timeout`

- Tipo: ***Entero (segundos)***
- Modos: ***Stateful***
- Valor por Omisión: ***2 seg***

- Nombre anterior: `--toFrag`
- Fuente: Ninguns (el parámetro denota un  [capricho de Linux](https://github.com/NICMx/NAT64/wiki/nf_defrag_ipv4-and-nf_defrag_ipv6#nf_defrag_ipv6---kernels-312-)).

Jool Stateful requiere un reensamble de fragmentos.

En kernes 3.13 y mas recientes, `--fragment-arrival-timeout` no hace nada en lo absoluto.

En kernels 3.12 y mas antiguos, el modulo de reensamble de fragmentos IPv6 (`nf_defrag_ipv6`) es un poco engañoso. Recolecta los fragmentos y en lugar de reensamblarlos, los manda a todos al resto del kernel en orden ascendente y muy rápido. Ya que Jool tiene que procesar todos los fragmentos de un solo paquete al mismo tiempo, tiene que esperar hasta que `nf_defrag_ipv6` los haya entregado todos.


`--fragment-arrival-timeout` es el tiempo que Jool esperará para que `nf_defrag_ipv6` ingrese todos los fragmentos de un paquete común. _No tiene nada que ver con esperar a que los fragmentosd lleguen al nodo_.

Como `nf_defrag_ipv6` ya ha esperado a que todos los fragmentos lleguen, deberia entregarlos en nanosegundos. Debido a esto, el valor por omisión de  
`--fragment-arrival-timeout` de 2 segunos es probablemente alto. Por otra parte, a menos de que haya un módulo desconocido desechando los paquetes en medio, todos los fragmentos deberían llegar inmediatamente, por lo tanto el temporizador nunca deberia de acabarse (incluso si estas siendo atacado).

Jool SIIT no necesita reensamblado de paquetes para nada.

Este comportamiento cambio desde Jool 3.2, donde `--toFrag` solía ser de hecho el tiempo que Jool esperaría para que los fragmentos llegaran al nodo.


### `--maximum-simultaneous-opens`

- Tipo: ***Integer***
- Modos: ***Stateful***
- Valor por Omisión: ***10***

- Nombre anterior: `--maxStoredPkts`
- Fuente: [RFC 6146, section 5.3](http://tools.ietf.org/html/rfc6146#section-5.3) (indirectamente)

Cuando un nodo (IPv4) externo intenta primero abrir una conexión y no hay ningun [registro BIB](misc-bib.html) para el, Jool normalmente contesta con un mensaje de error ICMP - Address Unreachable (type 3, code 1), ya que no puede saber a cual nodo IPv6 se está dirigiendo el paquete. 

En el caso de TCP, la situación es un poco más complicada por que el nodo IPv4 puede estar intentando una [Apertura Simultanea de conecciones TCP](https://github.com/NICMx/NAT64/issues/58#issuecomment-43537094). Para saber realmente que está pasando, Jool tiene que almacenar el paquete por 6 segundos.

`--maximum-simultaneous-opens` es el numero máximo de paquetes que Jool va almacenar al mismo tiempo.  El valor por omisión indica que puedes tener hasta 10 aperturas simultáneas, simultaneamente; Jool retrocederá a responder con un error ICMP en la número 11.


### `--source-icmpv6-errors-better`

- Tipo: ***Booleano***
- Modos: ***Stateful***
- Valor por Omisión: ***Apagado(0)***
- Sentido de traducción: ***IPv4 -> IPv6 (sólo errores ICMP)***

- Fuente: [Issue 132](https://github.com/NICMx/NAT64/issues/132)

Por alguna razón, el RFC 6146 quiere que el origen de los errores ICMPv6 sea igual que la dirección de destino de sus paquetes internos. Esto luce muy extraño.

Por ejemplo (TODO volver esto una imagen):

	n6 ----- j ----- R ----- n4

- n6 es un nodo IPv6; its address is 2001:db8::1.
- j es un Stateful NAT64. Su dirección IPv4 es 192.0.2.1. 
- Res un router IPv4. 192.0.2.6.
- n4 es un nodo IPv4. 203.0.113.13.

Digamos que el enlace entre R y n4 colapsa.

- n6 empaqueta en TCP n4: 2001:db8::1 -> 64:ff9b::203.0.113.13.

- j traduce y redirecciona: 192.0.2.1 -> 203.0.113.13

- R responde  ICMPv4 error "Host unreachable". The packet's addresses are 192.0.2.6 -> 192.0.2.1. The packet contains a TCP packet whose addresses are 192.0.2.1 -> 203.0.113.13.

- j traduce a un paquete IPv6 cuyas direcciones son 64:ff9b::203.0.113.13 -> 2001:db8::1. Su paquete interno lee 2001:db8::1 -> 64:ff9b::203.0.113.13.

[Esto interrumpe rastreos de ruta](https://github.com/NICMx/NAT64/issues/132). No deberia de haber sido 64:ff9b::**192.0.2.6** -> 2001:db8::1?

- `--source-icmpv6-errors-better` Desactivado hara que Jool obedezca el RFC 6146 (y que interrumpa los rastreos de ruta).
- `--source-icmpv6-errors-better` Encendido traducirá la dirección de origen externa directamente, simplemente agregando el prefijo.

### `--logging-bib`

- Tipo: ***Booleano***
- Modos: ***Stateful***
- Valor por Omisión: ***Apagado(0)***
- Sentido de traducción: ***IPv4 -> IPv6 & IPv6 -> IPv4***

- Fuente: [RFC 6888, section 4](http://tools.ietf.org/html/rfc6888#section-4)

Habilita el registro de la creación y destrucción de mapeos de direcciones. Si eres un proveedor de servicios, tu gobierno quizá te solicite que hagas esto.

El análisis de estos registros puede permitirte saber cual dirección IPv4 y Puerto enmascaró a alguno de tus nodos IPv6 internos en algun momento. Aquí hay una salida de ejemplo: 

	$ jool --logging-bib true
	$ dmesg
	[  312.493235] 2015/4/8 16:13:2 (GMT) - Mapped 2001:db8::5#19945 to 192.0.2.2#8208 (UDP)
	[  373.724229] 2015/4/8 16:14:3 (GMT) - Mapped 2001:db8::8#46516 to 192.0.2.2#12592 (TCP)
	[  468.675524] 2015/4/8 16:15:38 (GMT) - Forgot 2001:db8::5#19945 to 192.0.2.2#8208 (UDP)

En este ejemplo,

1. `2001:db8::5` utilizó el puerto(propio) 19945 para hablarle a alguien utilizando el protocolo UDP. Este alguien pensó que la dirección de  `2001:db8::5` era `192.0.2.2`, y que estaba utilizando el puerto 8208. 

2. Aproximadamente un minuto despues, `2001:db8::8` (en el puerto 46516) empezó a hablarle a alguien utilizando TCP. fue en enmascarada como `192.0.2.2`#12592. Esta conexión no ha terminado todavia.

3. Algunos momentos despues, Jool olvidó el mapeo (debido a inactividad, no por que el último paquete sucedió a las 16:15:38. "Cuanta inactividad" esta controlado por los timeouts - en este cao, el de [UDP](#udp-timeout)). En este punto, `192.0.2.2`#8208  esta libre de `2001:db8::5` y Jool lo puede reasignar.

Así que, si tu gobierno viene y dice "Detecté que alguien llamado `192.0.2.2`#8208 hizo algo ilegal a las 4:14 pm via UDP", puedes reportar que el culpable es `2001:db8::5`#19945 y liberarte de la culpa.

Hay muchas cosas importantes las cuales se tienen que tener en cuenta:

- La singularidad de cada paquete se extiende al protocolo. Si tu registro solo dice `se tradujo 2001:db8::5#19945 a 192.0.2.2#8208 (UDP)`, **no puedes** asumir que `2001:db8::5`#19945 es `192.0.2.2`#8208 en TCP también.

- Si tus nodos IPv6 comparten direcciones IPv4 entonces, los puertos importan.

- No hay información de a _quien_ le estaba hablando `2001:db8::5`. Esto es _bueno_; significa que le estas haciendo honor a la privacidad de tu cliente tanto como puedes.

- El registro utiliza GMT; quizá necesites convertir esto para efectos de comodidad.

Esto es falso por defecto por que genera enormes cantidades de registros mientras está activo (recuerda que necesitas infraestructura para mantenerlos). Toma en cuenta que los mapeos son vertidos en el _log del kernel_, asi que los mensajes serán mezclados junto con cualquier cosa que el kernel tenga que decir (incluyendo los mensajes de error de Jool, por ejemplo). Los mensajes de registro tendran [prioridad INFO](http://stackoverflow.com/questions/16390004/change-Valor por Omisión-console-loglevel-during-boot-up). 

Si loggear el destino tiene sentido para ti, ve `--logging-session` (abajo). Para cubrir con el REQ-12 del RFC 6888 quieres asingar el valor _true_ a `--loging-bib` y el valor _false_ a `--logging-session`.


### `--logging-session`

- Tipo: ***Booleano***
- Modos: ***Stateful***
- Valor por Omisión: ***Apagado(0)***
- Sentido de traducción: ***IPv4 -> IPv6 & IPv6 -> IPv4***

- Fuente: [RFC 6888, sección 4](http://tools.ietf.org/html/rfc6888#section-4)

Habilita el registro de todas las sesiones mientras son creadas y destruidas.

El formato es

	<fecha> <hora> (GMT) - <acción> sesión <nodo IPv6>|<representación IPv6 de un nodo IPv4>|<representación IPv4 de un nodo IPv6>|<nodo IPv4>|Protocolo

Aquí hay una salida de ejemplo:

	$ jool --logging-session true
	$ dmesg
	[ 3238.087902] 2015/4/8 17:1:47 (GMT) - Added session 1::5#47073|64:ff9b::c000:205#80|192.0.2.2#63527|192.0.2.5#80|TCP
	[ 3238.099997] 2015/4/8 17:1:47 (GMT) - Added session 1::5#47074|64:ff9b::c000:205#80|192.0.2.2#42527|192.0.2.5#80|TCP
	[ 3241.624104] 2015/4/8 17:1:51 (GMT) - Added session 1::5#33160|64:ff9b::c000:205#8080|192.0.2.2#15496|192.0.2.5#8080|TCP
	[ 3241.630905] 2015/4/8 17:1:51 (GMT) - Added session 1::5#33161|64:ff9b::c000:205#8080|192.0.2.2#7060|192.0.2.5#8080|TCP
	[ 3478.498559] 2015/4/8 17:5:48 (GMT) - Forgot session 1::5#47073|64:ff9b::c000:205#80|192.0.2.2#63527|192.0.2.5#80|TCP
	[ 3478.499758] 2015/4/8 17:5:48 (GMT) - Forgot session 1::5#47074|64:ff9b::c000:205#80|192.0.2.2#42527|192.0.2.5#80|TCP
	[ 3481.632214] 2015/4/8 17:5:51 (GMT) - Forgot session 1::5#33160|64:ff9b::c000:205#8080|192.0.2.2#15496|192.0.2.5#8080|TCP
	[ 3481.632342] 2015/4/8 17:5:51 (GMT) - Forgot session 1::5#33161|64:ff9b::c000:205#8080|192.0.2.2#7060|192.0.2.5#8080|TCP

Este registro es remarcablemente mas voluptuoso que [`--logging-bib`](#logging-bib), no sólo por que cada mensaje es mas largo, si no por que las sesiones son generadas y destruidas más frecuentemente que los registros BIB (cada registro BIB puede tener múltiples sesiones). Debido al REQ-12 del [RFC 6888 sección 4](http://tools.ietf.org/html/rfc6888#section-4), lo mas probable es que ni siquiera quieres la información extra que las sesiones te pueden proporcionar.


### `--zeroize-traffic-class`

- Tipo: ***Booleano***
- Modos: ***SIIT & Stateful***
- Valor por Omisión: ***APAGADO (0)***
- Sentido de traducción: ***IPv4 -> IPv6***

- Nombre anterior: `--setTC`
- Fuente: [RFC 6145, sección 4.1](http://tools.ietf.org/html/rfc6145#section-4.1)


El campo Clase de Tráfico de la [Cabecera IPv6](http://es.wikipedia.org/wiki/IPv6#Cabecera_fija) es muy similar al campo [Tipo de servicio](http://en.wikipedia.org/wiki/IPv4#Header) (Type of Service TOS) por sus siglas en inglés.

Si dejas esto desactivado, el valor del campo Tipo de Servicio será copiado directamente al campo Clase de Tráfico. Si lo activas, Jool siempre le asignara el valor **cero** al campo Clase de Tráfico.


### `--override-tos`

- Tipo: ***Booleano***
- Modos: ***SIIT & Stateful***
- Valor por Omisión: ***APAGADO (0)***
- Sentido de traducción: ***IPv6-> IPv4***

- Fuente: [RFC 6145, section 5.1](http://tools.ietf.org/html/rfc6145#section-5.1)
- Nombre anterior: `--setTOS`



El campo Clase de Tráfico de la [Cabecera IPv6](http://es.wikipedia.org/wiki/IPv6#Cabecera_fija) es muy similar al campo [Tipo de servicio](http://en.wikipedia.org/wiki/IPv4#Header) (Type of Service TOS) por sus siglas en inglés.

Si dejas esto desactivado, el valor del campo Clase de Tráfico será copiado directamente al campo Tipo de Servicio durante las traducciones de ***IPv6-> IPv4***. Si lo activas, Jool le asignará al campo Tipo de Servicio el valor indicado en el parámetro [`--tos`](#tos). 


### `--tos`

- Tipo: ***Integer***
- Modos: ***SIIT & Stateful***
- Valor por Omisión: ***Apagado(0)***
- Sentido de traducción: ***IPv6-> IPv4***

- Nombre anterior: `--TOS`

- Fuente: [RFC 6145, section 5.1](http://tools.ietf.org/html/rfc6145#section-5.1)

Valor que se va a asignar al campo Tipo de Servicio de los paquetes IPv4 durante la traducción de IPv6-a-IPv4. _Esto solo aplica cuando [`--override-tos`](#override-tos) está activo.


### `--allow-atomic-fragments`

En desuso. Ve [Atomic Fragments](esp-usr-flags-atomic.html).

### `--setDF`

En desuso. Ve [Atomic Fragments](esp-usr-flags-atomic.html).

### `--genFH`

En desuso. Ve [Atomic Fragments](esp-usr-flags-atomic.html).

### `--genID`

En desuso. Ve [Atomic Fragments](esp-usr-flags-atomic.html).

### `--boostMTU`

En desuso. Ve [Atomic Fragments](esp-usr-flags-atomic.html).

### `--amend-udp-checksum-zero`

- Tipo: ***Booleano***
- Modos: ***SIIT***
- Valor por Omisión: ***APAGADO (0)***
- Sentido de traducción: ***IPv4-> IPv6 (Solo UDP)***

- Fuente: [RFC 6145, sección 4.5](http://tools.ietf.org/html/rfc6145#section-4.5)

En IPv4, es legal para los paquetes UDP contener zero como checksum. Esto es por que la cuestion completa sobre UDP es que es poco confiable, y por lo tanto algunas veces el valor de validacion del checksum no justifica su costo.

En IPv6, zero es un valor checksum inválido para paquetes UDP.

- Si `--amend-udp-checksum-zero` está Activo y un paquete UDP IPv4 con valor cero en el campo checksum llega, Jool va a calcular su chechsum antes de traducirlo. Ten en cuenta que, esto quizá sea computacionalmente costo.

- Si `--amend-udp-checksum-zero` está Inactivo y un paquete UDP IPv4 con valor cero en el campo checksum llega, Jool va a desechar el paquete y registrar sus direcciones (with [Log Level](http://elinux.org/Debugging_by_printing#Log_Levels) KERN_DEBUG).

Esto no afecta a paquetes _fragmentados_ con valor cero en el campo checksum. SIIT Jool no reensambla, lo que significa que _no puede_ calcular el checksum. En estos casos, el paquete será desechado sin importar `--amend-udp-checksum-zero`.

El Stateful NAT64 de Jool _siempre_ procesa los checksums con valor cero de los paquetes UDP IPv4. Debido aa que reensambla, tambien lo hara para paquetes fragmentados. 


### `--randomize-rfc6791-addresses`

- Tipo: ***Booleano***
- Modos: ***SIIT***
- Valor por Omisión: ***Encendido(1)***
- Sentido de traducción: ***IPv6-> IPv4***

- Fuente: [Issue 130](https://github.com/NICMx/NAT64/issues/130)

Si el origen de un error ICMPv6 no puede ser traducido, el [RFC 6791](https://tools.ietf.org/html/rfc6791) quiere que asignemos una dirección IPv4 del [pool RFC 6791](usr-flags-pool6791.html)


- Si `--randomize-rfc6791-addresses` está Acitvo, Jool seguirá la sugerencia del RFC 6791, asignando una dirección aleatoria del pool.
- Si `--randomize-rfc6791-addresses` está Inactivo, Jool asignará la dirección mas alta especificada en la llave `hop limit` del pool.

Porque? se podria decir que [`hop limit`th es mejor](https://github.com/NICMx/NAT64/issues/130).

### `--mtu-plateaus`

- Tipo: ***Lista de Enteros separated by commas (If you want whitespace, remember to quote)***
- Modos: ***SIIT & Stateful***
- Valor por Omisión: ***65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68***
- Sentido de traducción: ***IPv4-> IPv6 (Solo Errores de ICMP)***

- Nombre anterior: `--plateaus`
- Fuente: [RFC 6145, sección 4.2](http://tools.ietf.org/html/rfc6145#section-4.2)

Cuando un paquete no debe de ser fragmentado y no encaja en un enlace por el que se supone debe pasar, el router del problema se supone debe de responder con un mensaje de error indicando _Fragmentation Needed_. Idealmente, este mensaje de error contendría el MTY del link para que el emisor original estuviera consciente del tamaño ideal del paquete y evite la fragmentación. Sin embargo, la especificación ICMPv4 no requiere que los routers incluyan esta información.

La compatibilidad con versiones anteriores le otorga a las estrategias de los emisóres IPv4 la capacidad de retroceder cuando encuentren tal situación, pero IPv6 siempre fue diseñado con el campo en mente. Entonces, so Jool traduce un mensaje ICMPv6 con valor cero en el campo MTU, *podria* suceder un caos (los resultados dependeran principalmente de la implementación IPv6 del cliente).

Para solucionar este problema, cuando Jool se encuentra intentando traducir un mensaje con valor cero en el campo MTU, reemplazara el MTU con el plateau mas grande el cual es mas bajo que la longitud total del campo del paquete original. Hay que reconocer, que esto podria o no ser el MTU correcto, pero es una suposición muy educada. Ve [este ejemplo](esp-usr-flags-plateaus.html) para obtener más detalles. Información más profunda puede ser encontrada en el [RFC 1191](http://tools.ietf.org/html/rfc1191).

Toma en cuenta que si `--boostMTU` está activado, el MTU será todavía 1280 incluso si el plateau relevante es menos que 1280.

No es necesario que ordenes los valores mientras los estas ingresando.
