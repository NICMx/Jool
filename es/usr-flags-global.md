---
language: es
layout: default
category: Documentation
title: --global
---

[Documentación](documentation.html) > [Aplicación de Espacio de Usuario](documentation.html#aplicacin-de-espacio-de-usuario) > `--global`

# \--global

## Índice

1. [Descripción](#descripcin)
2. [Sintaxis](#sintaxis)
3. [Ejemplos](#ejemplos)
4. [Llaves](#llaves)
	1. [`--enable`, `--disable`](#enable---disable)
	2. [`--address-dependent-filtering`](#address-dependent-filtering)
	3. [`--drop-icmpv6-info`](#drop-icmpv6-info)
	4. [`--drop-externally-initiated-tcp`](#drop-externally-initiated-tcp)
	5. [`--udp-timeout`](#udp-timeout)
	6. [`--tcp-est-timeout`](#tcp-est-timeout)
	7. [`--tcp-trans-timeout`](#tcp-trans-timeout)
	8. [`--icmp-timeout`](#icmp-timeout)
	9. [`--fragment-arrival-timeout`](#fragment-arrival-timeout)
	10. [`--maximum-simultaneous-opens`](#maximum-simultaneous-opens)
	11. [`--source-icmpv6-errors-better`](#source-icmpv6-errors-better)
	12. [`--logging-bib`](#logging-bib)
	13. [`--logging-session`](#logging-session)
	14. [`--zeroize-traffic-class`](#zeroize-traffic-class)
	15. [`--override-tos`](#override-tos)
	16. [`--tos`](#tos)
	17. [`--allow-atomic-fragments`](#allow-atomic-fragments)
		1. [`--setDF`](#setdf)
		2. [`--genFH`](#genfh)
		3. [`--genID`](#genid)
		4. [`--boostMTU`](#boostmtu)
	18. [`--amend-udp-checksum-zero`](#amend-udp-checksum-zero)
	19. [`--randomize-rfc6791-addresses`](#randomize-rfc6791-addresses)
	20. [`--mtu-plateaus`](#mtu-plateaus)
	21. [`--f-args`](#f-args)
	22. [`--handle-rst-during-fin-rcv`](#handle-rst-during-fin-rcv)

## Descripción

`--global` manipula varias variables internas de Jool. Un comando `--global` vacío imprime estas variables, y adicionar una llave y un valor modifica.

Es el modo por omisión de configuración de Jool, por lo que en realidad nunca es estrictamente necesario introducir explícitamente la bandera `--global`.

## Sintaxis

	(jool_siit | jool) [--global] [--display] [--csv]
	(jool_siit | jool) [--global] [--update] <llave> <valor>

## Ejemplos

Desplegar la configuración actual:

{% highlight bash %}
$ jool_siit --global
{% endhighlight %}

O simplemente:

{% highlight bash %}
$ jool_siit
{% endhighlight %}

Pausar a Jool:

{% highlight bash %}
$ jool --global --disable
{% endhighlight %}

Encender ***Filtrado Dependiente de Direccionamiento***:

{% highlight bash %}
$ # Valores válidos: {true, false, 1, 0, yes, no, on, off} <br />
$ jool --address-dependent-filtering true
{% endhighlight %}

Sobreescribir la ***Lista de Plateaus***:

{% highlight bash %}
$ jool_siit --mtu-plateaus "6000, 5000, 4000, 3000, 2000, 1000"
{% endhighlight %}

## Llaves

### `--enable`, `--disable`

- Nombre: ***HABILITA & DESHABILITA JOOL***
- Tipo: ***No Aplica***
- Modos: ***SIIT & NAT64***
- Valor por Omisión: *** Depende de las banderas empleadas al insertar JOOL ***

Reanuda y pausa la traducción de paquetes, respectivamente.

Esto puede ser utilizado para asegurar que Jool no traduzca paquetes hasta que la configuración se encuentre completa.

Mientras Jool está inactivo, *los temporizadores no serán pausados*. [Entradas BIB](bib.html), [sesiones](usr-flags-session.html) y [paquetes](#maximum-simultaneous-opens) pueden caducar mientras Jool se encuentra ocioso.

### `--address-dependent-filtering`

- Nombre: ***FILTRADO DEPENDIENTE DE DIRECCIONAMIENTO***
- Tipo: ***Booleano***
- Modos: ***NAT64***
- Valor por Omisión: ***APAGADO (0)***
- Fuente: Varios puntos del RFC 6146. Uno más o menos completo es la [sección 1.2.3](http://tools.ietf.org/html/rfc6146#section-1.2.3)

En resumen:

* `--address-dependent-filtering OFF` significa que Jool debe ser un NAT de cono completo.
* `--address-dependent-filtering ON` significa que Jool debe ser un NAT de cono restringido.
	
Explicación detallada:

Partiendo que _n6_ está hablando con _n4a_ mediante el NAT64:

![Fig.1: Legal chat](../images/usr-dropaddr-1.svg)

El [registro BIB](bib.html) es

| Dirección de transporte IPv6 | Dirección de transporte IPv4 | Protocolo |
|------------------------------|------------------------------|-----------|
| 2001:db8::1#10               | 192.0.2.1#10                 | TCP       |

_n4b_ se da cuenta del servicio de _n6_, quizá por que _n4a_ le dice sobre él:

![Fig.2: n4b finds about n6](../images/usr-dropaddr-2.svg)

Luego _n4b_ trata de conversar con _n6_ también:

![Fig.3: suspicious query](../images/usr-dropaddr-3.svg)

Ya que el registro BIB existe, _J_ sabe que _n4b_ significa  "2001:db8::1#10" cuando le dice "192.0.2.1#10", de modo que el paquete puede ser técnicamente traducido. Sin embargo, debido a las tablas de sesión, _J_ también sabe que _n6_ no ha estado conversando con _n4b_ en el pasado.

Si `--address-dependent-filtering` está deshabilitado, _J_ permitirá que el paquete de _n4b_ se traduzca. Si `--address-dependent-filtering` está encendido, _J_ desechará el paquete de _n4b_ y responderá con un error ICMP de tipo "Comunicación prohibida". Esto restringe efectivamente cualquier intento de comunicación iniciado desde IPv4, aún si hay registros BIB (ya sean estáticos o dinámicos).

* Cuando el NAT64 es utilizado para publicar un servicio que solo es soportado bajo IPv6 a la Internet IPv4, tiene sentido que `--address-dependent-filtering` esté deshabilitado. Esto es porque se espera que los clientes se enteren del servicio IPv6 por su cuenta, ya que el servidor normalmente no inicia conversaciones.
* Cuando el NAT64 es utilizado para permitir a los nodos IPv6 navegar sobre la Internet en IPv4, tiene sentido que `--address-dependent-filtering` esté encendido. Dado que los nodos clientes de IPv6 eligen sus puertos de manera aleatoria, este mecanismo sirve para descartar el acceso a nodos aleatorios externos que pretendan adivinar estos puertos.

Si `--address-dependent-filtering` está encendido, podría impedir métodos de recorrido de NAT como STUN, o al menos hacer imposibles algunos modos de operación.

### `--drop-icmpv6-info`

- Nombre: ***Tirar pings de IPv6?***
- Tipo: ***Booleano***
- Modos: ***NAT64***
- Valor por Omisión: ***APAGADO (0)***
- Sentido de traducción: ***IPv6 -> IPv4 (solo mensajes de ICMP informativos)***
- Fuente: [RFC 6146, sección 3.5.3](http://tools.ietf.org/html/rfc6146#section-3.5.3)

Si se activa esta bandera, los mensajes del tipo echo y echo reply serán bloqueados mientras estén siendo traducidos de ICMPv6 a ICMPv4.

Por alguna razón el estándar no dicta que debamos bloquear mensajes de ICMPv4 a ICMPv6, pero como se necesita tanto una solicitud y una respuesta para un eco exitoso, el resultado parece ser el mismo.

Esta regla no afecta mensajes ICMP de tipo error.


### `--drop-externally-initiated-tcp`

- Nombre: ***Tirar TCP iniciado desde IPv4?***
- Tipo: ***Booleano***
- Modos: ***NAT64***
- Valor por Omisión: ***APAGADO (0)***
- Fuente: [RFC 6146, sección 3.5.2.2](http://tools.ietf.org/html/rfc6146#section-3.5.2.2)

`--drop-externally-initiated-tcp` encendido evita que nodos de IPv4 puedan iniciar comunicaciones de TCP.

Por supuesto, esto no bloqueará el tráfico TCP si algún nodo IPv6 es quien lo solicita.

### `--udp-timeout`

- Nombre: ***Tiempo de vida de sesiones UDP***
- Tipo: ***Entero (segundos)***
- Modos: ***NAT64***
- Valor por Omisión: ***300 segundos (5 minutos)***
- Fuente: [RFC 6146, sección 3.5.1](http://tools.ietf.org/html/rfc6146#section-3.5.1)

Cuando una sesión UDP ha estado inactiva por el período de tiempo especificado aquí, su registro será removido de la base de datos automáticamente.

Cuando se modifica este valor, los tiempos de vida de todas las sesiones UDP ya existentes también serán actualizados.

### `--tcp-est-timeout`

- Nombre: ***Tiempo de tolerancia a sesiones TCP establecidas***
- Tipo: ***Entero (segundos)***
- Modos: ***NAT64***
- Valor por Omisión: ***7200 segundos (2 horas)***
- Fuente: [RFC 6146 sección 3.5.2.2](http://tools.ietf.org/html/rfc6146#section-3.5.2.2)

Cuando una conexión TCP ha permanecido inactiva por el período de tiempo especificado aquí, su existencia será cuestionada. Jool enviará un paquete de sondeo a uno de los puntos y eliminará la sesión si una respuesta no es recibida antes de que transcurran `--tcp-trans-timeout` segundos.

Cuando se modifica este valor, los tiempos de vida de todas las sesiones TCP establecidas también serán actualizados.


### `--tcp-trans-timeout`

- Nombre: ***Tiempo de vida de sesiones TCP transitorias***
- Tipo: ***Entero (segundos)***
- Modos: ***NAT64***
- Valor por Omisión: ***2400 segundos (4 minutos)***
- Fuente: [RFC 6146, secciones derivadas de 3.5.2](http://tools.ietf.org/html/rfc6146#section-3.5.2)

Cuando una sesión TCP transitoria ha estado inactiva durante el período de tiempo especificado aquí, su registro será removido de la base de datos automáticamnete. Una sesión "transitoria" es una en la cual el handshake de TCP no ha sido completado, está siendo terminada por los puntos, o está técnicamente establecida pero ha permanecido inactiva por `--tcp-est-timeout` segundos.

Cuando se modifica este valor, los tiempos de vida de todas las sesiones TCP transitorias ya existentes también serán actualizados.


### `--icmp-timeout`

- Nombre: ***Tiempo de vida de sesiones ICMP***
- Tipo: ***Entero (segundos)***
- Modos: ***NAT64***
- Valor por Omisión: ***60 segundos (1 minuto)***
- Fuente: [RFC 6146, sección 3.5.3](http://tools.ietf.org/html/rfc6146#section-3.5.3)

Cuando una sesión ICMP ha estado inactiva por el período de tiempo especificado aquí, su registro será removido de la base de datos automáticamente.

Cuando se modifica este valor, los tiempos de vida de todas las sesiones ICMP ya existentes también serán actualizados.

### `--fragment-arrival-timeout`

- Nombre: ***Tiempo de vida de fragmentos***
- Tipo: ***Entero (segundos)***
- Modos: ***NAT64***
- Valor por Omisión: ***2 segundos***
- Fuente: Ninguna (el parámetro es una respuesta a un [capricho de Linux]({{ site.repository-url }}/wiki/nf_defrag_ipv4-and-nf_defrag_ipv6#nf_defrag_ipv6---kernels-312-)).

NAT64 Jool requiere reensamblaje de fragmentos.

En kernes 3.13 y más recientes, `--fragment-arrival-timeout` no tiene ningún efecto.

En kernels 3.12 y más antiguos, el módulo de reensamblaje de fragmentos IPv6 (`nf_defrag_ipv6`) es un poco engañoso. Lo que hace es recolectar fragmentos y despacharlos por separado (en lugar de juntarlos). Ya que Jool tiene que procesar todos los fragmentos de un solo paquete al mismo tiempo, tiene que esperar hasta que `nf_defrag_ipv6` los haya entregado todos.

`--fragment-arrival-timeout` es el tiempo que Jool esperará para que `nf_defrag_ipv6` despache todos los fragmentos de un paquete común. _No tiene nada que ver con esperar a que los fragmentos lleguen al nodo_.

Como `nf_defrag_ipv6` ya ha esperado a que todos los fragmentos lleguen, debería entregarlos en nanosegundos. Debido a esto, el valor por omisión de `--fragment-arrival-timeout` de 2 segunos es probablemente excesivo. Por otra parte, a menos de que haya un módulo desconocido desechando los paquetes enmedio, todos los fragmentos deberían llegar inmediatamente, por lo que el temporizador nunca debería expirar (incluso si el nodo está siendo atacado).

Jool SIIT no necesita reensamblaje de paquetes.


### `--maximum-simultaneous-opens`

- Nombre: ***Máximo número tolerable de aperturas simultaneas de TCP***
- Tipo: ***Entero***
- Modos: ***NAT64***
- Valor por Omisión: ***10***
- Fuente: [RFC 6146, section 5.3](http://tools.ietf.org/html/rfc6146#section-5.3) (indirectamente)

Cuando un nodo (IPv4) externo intenta abrir una conexión y no hay ningún [registro BIB](bib.html) para él, Jool normalmente contesta con un mensaje de error ICMP - Dirección inalcanzable (tipo 3, código 1), ya que no puede saber a cual nodo IPv6 se está dirigiendo el paquete. 

En el caso de TCP, la situación es un poco más complicada porque el nodo IPv4 puede estar intentando una [Apertura Simultánea de conexiones TCP]({{ site.repository-url }}/issues/58#issuecomment-43537094). Para saber realmente qué está pasando, Jool tiene que almacenar el paquete por 6 segundos.

`--maximum-simultaneous-opens` es el numero máximo de paquetes que Jool va almacenar al mismo tiempo. El valor por omisión indica que se pueden tener hasta 10 aperturas simultáneas, "simultaneamente"; si otra apertura simultanea llega a ocurrir, Jool tendrá que ignorarla respondiendo el error ICMP.


### `--source-icmpv6-errors-better`

- Nombre: ***Mejorar la dirección fuente de errores ICMPv6***
- Tipo: ***Booleano***
- Modos: ***NAT64***
- Valor por Omisión: ***Apagado (0)***
- Sentido de traducción: ***IPv4 -> IPv6 (solo errores ICMP)***
- Fuente: [Issue 132]({{ site.repository-url }}/issues/132)

Por alguna razón, el RFC 6146 quiere que el origen de los errores ICMPv6 sea igual que la dirección de destino de sus paquetes internos. Esto no es ideal.

![Figura 4: Diagrama de mejora de fuente](../images/network/src-icmp6-better.svg)

Si el enlace entre _R_ y _n4_ colapsa, el siguiente flujo puede suceder:

- _n6_ escribe por TCP a _n4_: 2001:db8::1 -> 64:ff9b::203.0.113.13.
- T traduce y forwardea: 192.0.2.1 -> 203.0.113.13
- _R_ responde el error ICMPv4 "Host inalcanzable". Las direcciones del paquete de error son 192.0.2.6 -> 192.0.2.1.
- _T_ traduce eso a un paquete IPv6 cuyas direcciones son 64:ff9b::203.0.113.13 -> 2001:db8::1 (porque esta es la inversa del primer paquete).

[Esto interrumpe rastreos de ruta]({{ site.repository-url }}/issues/132). No debería haber sido 64:ff9b::**192.0.2.6** -> 2001:db8::1?

- `--source-icmpv6-errors-better` desactivado hará que Jool obedezca al RFC 6146 (lo cual rompe rastreos de ruta).
- `--source-icmpv6-errors-better` encendido traducirá la dirección de origen externa directamente, simplemente agregando el prefijo.

### `--logging-bib`

- Nombre: ***Escribir entradas BIB en bitácora***
- Tipo: ***Booleano***
- Modos: ***NAT64***
- Valor por Omisión: ***Apagado (0)***
- Sentido de traducción: ***IPv4 -> IPv6 & IPv6 -> IPv4***
- Fuente: [RFC 6888, sección 4](http://tools.ietf.org/html/rfc6888#section-4)

Habilita el registro de creación y destrucción de mapeos de direcciones. Proveedores de servicios pueden requerir hacer esto debido a legislaciones.

El análisis de estos registros revela cuáles direcciones de transporte se utilizaron para enmascarar nodos IPv6 internos en un momento dado. Aquí hay una salida de ejemplo: 

	$ jool --logging-bib true
	$ dmesg
	[  312.493235] 2015/4/8 16:13:2 (GMT) - Mapped 2001:db8::5#19945 to 192.0.2.2#8208 (UDP)
	[  373.724229] 2015/4/8 16:14:3 (GMT) - Mapped 2001:db8::8#46516 to 192.0.2.2#12592 (TCP)
	[  468.675524] 2015/4/8 16:15:38 (GMT) - Forgot 2001:db8::5#19945 to 192.0.2.2#8208 (UDP)

En este ejemplo,

1. `2001:db8::5` utilizó el puerto (propio) 19945 para hablar con algún nodo en IPv4 utilizando el protocolo UDP. El nodo IPv4 pensó que la dirección de `2001:db8::5` era `192.0.2.2`, y que estaba utilizando el puerto 8208.
2. Aproximadamente un minuto después, `2001:db8::8` (en el puerto 46516) empezó a hablar a algún nodo IPv4 utilizando TCP. Su conexión fue en enmascarada como `192.0.2.2#12592`. Esta conexión no ha terminado todavía.
3. Algunos momentos después, Jool olvidó el mapeo (debido a inactividad, no porque el último paquete sucedió a las 16:15:38. "Cuánta inactividad" está controlada por los timeouts - en este cao, el de [UDP](#udp-timeout)). En este punto, `192.0.2.2#8208` está libre de `2001:db8::5` y Jool lo puede reasignar.

Si el gobierno viene y dice "Detecté que alguien llamado `192.0.2.2#8208` hizo algo ilegal a las 4:14 pm via UDP", es necesario reportar que el culpable es `2001:db8::5#19945`, no el dueño del NAT64.

Hay varios factores importantes que se tienen que tener en cuenta:

- La singularidad de cada paquete se extiende al protocolo. Si el registro solo dice "se tradujo 2001:db8::5#19945 a 192.0.2.2#8208 (UDP)", **no** se debe asumir `2001:db8::5`#19945 es `192.0.2.2`#8208 en TCP también.
- Si los nodos IPv6 comparten direcciones IPv4, los puertos importan.
- No hay información de _a quién_ estaba hablando `2001:db8::5`. _Esto es bueno_; significa que se está respetando la privacidad del cliente.
- El registro utiliza GMT; quizá se necesite convertir esto para comodidad.

Esto es falso por defecto porque genera enormes cantidades de mensajes en log mientras está activo (_es necesaria infraestructura para mantenerlos_). Los mapeos son vertidos en el _log del kernel_, de modo que los mensajes serán mezclados junto con cualquier otra cosa que el kernel tenga que decir ([incluyendo los mensajes de error de Jool, por ejemplo](logging.html)). Los mensajes de registro tendrán [prioridad INFO](http://stackoverflow.com/questions/16390004/change-Valor por Omisión-console-loglevel-during-boot-up).

Si también se desea mantener registro del destino, ver `--logging-session` (abajo). Para cumplir con el REQ-12 del RFC 6888 se debe encender `--loging-bib` y apagar `--logging-session`.


### `--logging-session`

- Nombre: ***Escribir sesiones en bitácora***
- Tipo: ***Booleano***
- Modos: ***NAT64***
- Valor por Omisión: ***Apagado (0)***
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

Este registro es remarcablemente más voluptuoso que [`--logging-bib`](#logging-bib), no solo porque cada mensaje es más largo, si no porque las sesiones son generadas y destruidas más frecuentemente que los registros BIB (cada registro BIB puede tener múltiples sesiones). Debido al REQ-12 del [RFC 6888 sección 4](http://tools.ietf.org/html/rfc6888#section-4), la información adicional que las sesiones proveen probablemente no tiene propósito.


### `--zeroize-traffic-class`

- Nombre: ***Limpiar Traffic Class***
- Tipo: ***Booleano***
- Modos: ***SIIT & NAT64***
- Valor por Omisión: ***APAGADO (0)***
- Sentido de traducción: ***IPv4 -> IPv6***
- Fuente: [RFC 6145, sección 4.1](http://tools.ietf.org/html/rfc6145#section-4.1)


El campo _Traffic Class_ de la [Cabecera IPv6](http://es.wikipedia.org/wiki/IPv6#Cabecera_fija) es muy similar al campo [_TOS_ de IPv4](http://en.wikipedia.org/wiki/IPv4#Header).

Si se deja `--zeroize-traffic-class` desactivado, TOS será copiado a Traffic Class durante traducciones. Si se activa, Traffic Class siempre será cero.


### `--override-tos`

- Nombre: ***Sobreescribir TOS***
- Tipo: ***Booleano***
- Modos: ***SIIT & NAT64***
- Valor por Omisión: ***APAGADO (0)***
- Sentido de traducción: ***IPv6-> IPv4***
- Fuente: [RFC 6145, sección 5.1](http://tools.ietf.org/html/rfc6145#section-5.1)


El campo _Traffic Class_ de la [Cabecera IPv6](http://es.wikipedia.org/wiki/IPv6#Cabecera_fija) es muy similar al campo [_TOS_ de IPv4](http://en.wikipedia.org/wiki/IPv4#Header).

Si se deja `--override-tos` desactivado, Traffic Class será copiado a TOS durante traducciones. Si se activa, Traffic Class siempre será [`--tos`](#tos).


### `--tos`

- Nombre: ***TOS***
- Tipo: ***Entero***
- Modos: ***SIIT & NAT64***
- Valor por Omisión: ***Apagado(0)***
- Sentido de traducción: ***IPv6-> IPv4***
- Fuente: [RFC 6145, sección 5.1](http://tools.ietf.org/html/rfc6145#section-5.1)

Valor que se va a asignar al campo TOS (Tipo de Servicio) de los paquetes IPv4 durante la traducción de IPv6 a IPv4. _Esto solo aplica cuando [`--override-tos`](#override-tos) está activo_.


### `--allow-atomic-fragments`

Deprecado.

### `--setDF`

Deprecado.

### `--genFH`

Deprecado.

### `--genID`

Deprecado.

### `--boostMTU`

Deprecado.

### `--amend-udp-checksum-zero`

- Nombre: ***Corregir Checksum cero en UDP***
- Tipo: ***Booleano***
- Modos: ***SIIT***
- Valor por Omisión: ***APAGADO (0)***
- Sentido de traducción: ***IPv4-> IPv6 (Solo UDP)***
- Fuente: [RFC 6145, sección 4.5](http://tools.ietf.org/html/rfc6145#section-4.5)

En IPv4, es legal que los paquetes UDP contengan cero como checksum. Esto es porque UDP es poco confiable por diseño, y por lo tanto algunas veces el valor que da la validacion de checksum no justifica su costo.

En IPv6, está prohibido que el checksum de paquetes UDP sea cero.

- Si `--amend-udp-checksum-zero` está activo y llega un paquete IPv4/UDP con checksum cero, Jool va a calcular su checksum antes de traducirlo. Esto puede ser costoso.
- Si `--amend-udp-checksum-zero` está inactivo y llega un paquete IPv4/UDP con checksum cero, Jool va a desechar el paquete y registrar sus direcciones en bitácora (con [Log Level](http://elinux.org/Debugging_by_printing#Log_Levels) KERN_DEBUG).

Esto no afecta a paquetes _fragmentados_ con checksum cero. SIIT Jool no reensambla, por lo que _no puede_ calcular el checksum. En estos casos, el paquete será desechado sin importar `--amend-udp-checksum-zero`.

NAT64 Jool _siempre_ procesa los checksums con valor cero de los paquetes UDP IPv4. Debido a que reensambla, tambien lo hará para paquetes fragmentados. 


### `--randomize-rfc6791-addresses`

- Nombre: ***Aleatorizar direcciones de pool6791***
- Tipo: ***Booleano***
- Modos: ***SIIT***
- Valor por Omisión: ***Encendido (1)***
- Sentido de traducción: ***IPv6-> IPv4***
- Fuente: [Issue 130]({{ site.repository-url }}/issues/130)

Si el origen de un error ICMPv6 no puede ser traducido, el [RFC 6791](https://tools.ietf.org/html/rfc6791) dicta que se le asigne una dirección IPv4 de [pool6791](pool6791.html).

- Si `--randomize-rfc6791-addresses` está activo, Jool seguirá la sugerencia del RFC 6791, asignando una dirección aleatoria de pool6791.
- Si `--randomize-rfc6791-addresses` está inactivo, Jool asignará la dirección número _hop limit_ de pool6791 (donde _hop limit_ es un campo de la [cabecera IPv6](http://es.wikipedia.org/wiki/IPv6#Cabecera_fija) del paquete).

Esto existe porque se puede argumentar que ["dirección número _hop limit_" es mejor]({{ site.repository-url }}/issues/130).

### `--mtu-plateaus`

- Nombre: ***Pleateaus para corregir MTU***
- Tipo: ***Lista de Enteros separados por comas (si se necesitan espacios en blanco, requiere comillas)***
- Modos: ***SIIT & NAT64***
- Valor por Omisión: ***"65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68"***
- Sentido de traducción: ***IPv4-> IPv6 (Solo Errores de ICMP)***
- Fuente: [RFC 6145, sección 4.2](http://tools.ietf.org/html/rfc6145#section-4.2)

Cuando un paquete que no debe ser fragmentado no encaja en un enlace de su camino, el enrutador que encuentra el problema debe responder un mensaje ICMP error. Idealmente, este error debe contener el MTU del enlace para que el emisor pueda ajustar su paquete acordemente. Sin embargo, la especificación original de ICMPv4 no requería que los enrutadores incluyeran esta información, de modo que implementaciones antiguas pueden omitirlo.

La compatibilidad con versiones anteriores gracia a IPv4 con estrategias para enfrentar MTUs desconocidos, pero IPv6 no fue diseñado con esta mentalidad. Por lo tanto, si Jool traduce un mensaje ICMPv6 y deja el MTU indefinido, el emisor IPv6 puede verse en problemas.

Por lo tanto, cuando Jool se encuentra intentando traducir un error ICMP sin MTU, asignará el plateau más grande que no sobrepase la longitud total del paquete original. En realidad, este puede o no ser el MTU correcto, pero es una suposición muy educada. [Este ejemplo](usr-flags-plateaus.html) expone más detalles. Información más profunda puede ser encontrada en el [RFC 1191](http://tools.ietf.org/html/rfc1191).

Nótese que el mínimo MTU en IPv6 es 1280, de modo que cualquier plateau menor a 1280 será ajustado.

No es necesario que se ordenen los valores mientras se ingresan.

### `--f-args`

- Nombre: ***Argumentos para `F()`***
- Tipo: ***Entero***
- Valor por omisión: ***11 (binario 1011)***
- Modos: ***NAT64***
- Sentido de traducción: ***IPv6 -> IPv4***
- Fuente: [Issue 195](https://github.com/NICMx/Jool/issues/195)

Es [recomendado]({{ site.draft-nat64-port-allocation }}) que la dirección fuente IPv4 que se elija para enmascarar un socket de IPv6 sea lo más aleatoria posible, pero al mismo tiempo, que sea dependiente de varias propiedades de la conexión. La aleatoriedad es deseada para enforzar la defensa contra intercepciones de conexión maliciosas, y la dependencia sirve para que conexiones similares tengan máscaras similares (lo cual es esperado por ciertos protocolos de más alto nivel).

En otras palabras, cuando se traduce un paquete IPv6 de una nueva conexión, el traductor emplea una función (`F`). Esta función hashea ciertos campos, convirtiéndolos en una dirección de transporte (`m`) de pool4, la cual se usa como fuente del paquete resultante:

	F(Dirección fuente IPv6, Dirección destino IPv6, Puerto destino) = m

(La implementación de `F` es el [Algoritmo 3 del RFC 6056](https://tools.ietf.org/html/rfc6056#page-14).)

Los siguientes flujos de paquetes ejemplifican el trabajo de `F`:

![Fig.5: --f-args, ejemplo](../images/network/f-args.svg)

`2001:db8::1` escribe el paquete `2001:db8::1#5000 -> 64:ff9b::192.0.2.1#80`. Jool necesita reservar una máscara, de modo que `F` resulta en el hash `203.0.113.6#6789`:

	F(2001:db8::1, 64:ff9b::192.0.2.1, 80) = 203.0.113.6#6789

Por lo tanto, Jool guarda la entrada BIB `2001:db8::1#5000 | 203.0.113.6#6789` y el paquete se convierte en `203.0.113.6#6789 -> 192.0.2.1#80`.

A continuación, otro nodo de IPv6 (`2001:db8::2`) abre un socket hacia alguien más. El nuevo paquete es `2001:db8::2#6000 -> 64:ff9b::198.51.100.4#443` y `F` produce otra dirección porque ha recibido otros argumentos:

	F(2001:db8::2, 64:ff9b::198.51.100.4, 443) = 203.0.113.25#4421

Jool guarda la entrada BIB `2001:db8::2#6000 | 203.0.113.25#4421` y el paquete se traduce como `203.0.113.25#4421 -> 198.51.100.4#443`.

Por último, el mismo nodo de IPv6 necesita abrir otro socket hacia el mismo servicio IPv4. Esto generalmente sucede en aplicaciones con múltiples sockets, tales como juegos (El servidor, por supuesto, espera que la dirección del cliente sea la misma en ambas conexiones). El nuevo paquete es `2001:db8::2#7000 -> 64:ff9b::198.51.100.4#443`. Como los argumentos relevantes son los mismos, `F` da el mismo resultado que en el flujo anterior.

	F(2001:db8::2, 64:ff9b::198.51.100.4, 443) = 203.0.113.25#4421

No es posible que dos entradas BIB tengan la misma dirección de transporte IPv4 (acaba de suceder una _colisión_), por lo que Jool elige una cercana. Se genera la entrada BIB `2001:db8::2#7000 | 203.0.113.25#4422` y el paquete se traduce como `203.0.113.25#4422 -> 198.51.100.4#443`.

Aquí se puede observar que el mecanismo está diseñado para que las máscaras se distribuyan aleatoriamente a través del dominio de pool4, a menos de que el nodo IPv4 espere una dirección de transporte fuente que sea similar a una de las de una conexión anterior. (Incluir el puerto fuente en `F` rompería esto.)

Lo anterior normalmente funciona sin problemas. Sucede, sin embargo, que existe al menos un protocolo (FTP utilizando EPSV) en el cual el servidor espera que el cliente abra una segunda conexión en una fuente similar, pero también se espera que esta conexión interactúe con otro puerto del servidor. El mecanismo explicado arriba generalmente rompe esta segunda conexión porque el puerto destino aleatoriza al hash de `F`, de modo que `m` generalmente resulta no ser una fuente similar.

`--f-args` permite incluir y excluir argumentos de `F`. Es posible usarlo para idear una combinación de argumentos que va a ser más amigable con protocolos de aplicación que hacen suposiciones extrañas respecto a las direcciones de un paquete. Es necesario mantener en mente, sin embargo, que excluir argumentos de `F` incrementa la frecuencia de colisiones debido a la reducción de aleatoriedad, lo cual puede ser costoso (para los estándares del kernel).

`--f-args` es un campo de bits. Cada bit en `--f-args` representa un argumento para `F`. Si se activa el bit, el argumento se incluye. Estos son los argumentos disponibles (desde el más hacia el menos significativo):

1. Dirección fuente (IPv6)
2. Puerto fuente
3. Dirección destino (IPv6)
4. Puerto destino

A modo de ejemplo, el valor por defecto (decimal 11, binario 1011) excluye al puerto fuente de la ecuación.

Para solucionar el problema de FTP/EPSV, es preciso remover el puerto destino de `F`. Esto obliga a que todas las conexiones que involucren a los mismos nodos sean enmascaradas similarmente.

Desafortunadamente, `--f-args` solamente puede ser introducido mediante su representación en decimal. Esto es posible:

	$ jool --f-args 10

Esto no lo es:

	$ jool --f-args 0b1010

### `--handle-rst-during-fin-rcv`

- Nombre: ***"Responder a la bandera RST durante los estados V4 FIN RCV y V6 FIN RCV"***
- Tipo: ***Booleano***
- Valor ***por omisión: Apagado (0)***
- Modes: ***NAT64***
- Sentido de traducción: ***IPv4 -> IPv6 & IPv6 -> IPv4***
- Fuente: [Issue 212](https://github.com/NICMx/Jool/issues/212)

Algunas implementaciones tienen el mal hábito de terminar conexiones de TCP de manera poco elegante. En lugar de realizar un FIN handshake estándar (FIN, FIN-ACK, ACK), terminan flujos abruptamente (FIN, RST). La especificación de NAT64 no considera esto, de modo que los mapeos relevantes se mantienen vivos por `--tcp-est-timeout` segundos. Dado que la conexión está siendo terminada, `--tcp-trans-timeout` segundos sería más apropiado. Esto normalmente significa que estos mapeos inactivos se mantienen en la base de datos por más tiempo del ideal.

Si se activa `--handle-rst-during-fin-rcv`, Jool va a asignar el tiempo de vida transitorio a conexiones terminadas con un FIN seguido por un RST. Esto es comportamiento no estándar, pero debería optimizar el uso de pool4.

El único problema conocido con activar `--handle-rst-during-fin-rcv` es que hace que un atacante sea capaz de prematuramente terminar conexiones que cumplan con las siguientes condiciones:

- Están ociosas (Más de `--tcp-trans-timeout` segundos entre paquetes).
- Uno de los extremos ya ha enviado un FIN.

