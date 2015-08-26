---
layout: documentation
title: Documentación - SIIT - Ejemplo básico 
---

[Documentación](esp-doc-index.html) > [Ejemplos de uso](esp-doc-index.html#ejemplos-de-uso) > SIIT

# SIIT: Ejemplo de Uso

## Índice

1. [Introducción](#introduccion)
2. [Red de ejemplo](#red-de-ejemplo)
	1. [`Configuración de Nodos en IPv6`] (#nodos-ipv6)
	2. [`Configuración de Nodos en IPv4`] (#nodos-ipv4)
	3. [`Configuración de Nodo Traductor`] (#nodo-jool)
3. [Jool](#jool)
4. [Pruebas](#pruebas)
	1. [`Conectividad de IPv4 a IPv6`] (#ping4to6)
	2. [`Conectividad de IPv6 a IPv4`] (#ping6to4)
	3. [`Conectividad a un Web Server en IPv4`] (#WebServer-ipv4)
	4. [`Conectividad a un Web Server en IPv6`] (#WebServer-ipv6)
5. [Deteniendo Jool](#deteniendo-jool)
6. [Lecturas adicionales](#lecturas-adicionales)

## Introducción

Este documento explica cómo ejecutar Jool en modo SIIT. Si no tienes nociones de este tipo de traducción ingresa a [SIIT Tradicional](esp-intro-nat64.html#siit-tradicional).

En cuanto a software, solo se necesita una [instalación exitosa del Servidor Jool](esp-mod-install.html). El configurador queda fuera del alcance de esta página.

Para la implementación de las pruebas, puedes usar alternativamente máquinas virtuales u otro tipo de interfaces, dado que Jool no está ligado al uso exclusivo de interfaces físicas del tipo "_ethX_".

## Red de ejemplo

![Figura 1 - Red de ejemplo](images/network/vanilla.svg)

No es necesario que des de alta todos los nodos que se muestran en el diagrama; puedes lograrlo con solo 3 nodos: _A_, _T_ y _V_. El resto son muy similares a _A_ y _V_ y son mostrados para propósitos ilustrativos.

Considera que tienes un bloque de direcciones 198.51.100.8/29 para distribuirlo entre tus nodos IPv6.

Jool requiere que _T_ tenga instalado Linux. El resto de los nodos puede tener cualquier otro sistema operativo, siempre y cuando manejen TCP/IP.

Sin embargo para efectos de simplicidad, los ejemplos aqui mencionados asumen que todos los nodos tienen instalado Linux y que todo esta siendo configurado estáticamente usando el bien-conocido comando `ip`. Y además, todo el tráfico será redirigido por defecto hacia _T_.

Dependiendo de tu distribución de linux, la forma de cómo deshabilitar el administrador de red puede variar. Esto se requiere, para que tomes control sobre las direcciones y rutas de tus interfaces; de otra forma, los comandos `ip` pudieran no tener efecto.

### `Configuración de Nodos en IPv6`

Para los nodos de _A_ a _E_, ejecuta la siguiente secuencia de comandos con permisos de administrador:

{% highlight bash %}
user@A:~# service network-manager stop
user@A:~# ip link set eth0 up
user@A:~# # Replace ".8" depending on which node you're on.
user@A:~# ip addr add 2001:db8::198.51.100.8/120 dev eth0
user@A:~# ip route add default via 2001:db8::198.51.100.1
{% endhighlight %}


### `Configuración de Nodos en IPv4`

Para los nodos de _V_ a _Z_, ejecuta la siguiente secuencia de comandos con permisos de administrador:

{% highlight bash %}
user@V:~# service network-manager stop
user@V:~# ip link set eth0 up
user@V:~# # Replace ".16" depending on which node you're on.
user@V:~# ip addr add 192.0.2.16/24 dev eth0
user@V:~# ip route add default via 192.0.2.1
{% endhighlight %}

### `Configuración del Nodo Traductor`

Para el Nodo _T_, ejecuta la siguiente secuencia de comandos con permisos de administrador:

{% highlight bash %}
user@T:~# service network-manager stop
user@T:~# 
user@T:~# ip link set eth0 up
user@T:~# ip addr add 2001:db8::198.51.100.1/120 dev eth0
user@T:~# 
user@T:~# ip link set eth1 up
user@T:~# ip addr add 192.0.2.1/24 dev eth1
{% endhighlight %}

Hasta aqui, no hemos convertido a _T_ en un traductor todavia, pues el servicio está dado de baja; por lo cual, los nodos desde _A_ hasta _E_ no pueden interactuar todavía con los nodos _V_ hasta _Z_. Pero, quizá quieras asegurarte de que _T_ puede comunicarse con todos los nodos antes de continuar.

La única precaución que debes tener en mente antes de activar Jool (o lidiar con IPv6 en general) son los offloads. Offloading es una característica de los nodos terminales, y para los que no lo son esto es un problema, por lo cual es importante apagarlos en todos los ruteadores. [Lee este documento](esp-misc-offloading.html) si quieres conocer más detalles sobre esta problemática.

Hazlo por medio de `ethtool`:

{% highlight bash %}
user@T:~# ethtool --offload eth0 tso off
user@T:~# ethtool --offload eth0 ufo off
user@T:~# ethtool --offload eth0 gso off
user@T:~# ethtool --offload eth0 gro off
user@T:~# ethtool --offload eth0 lro off
user@T:~# ethtool --offload eth1 tso off
user@T:~# ethtool --offload eth1 ufo off
user@T:~# ethtool --offload eth1 gso off
user@T:~# ethtool --offload eth1 gro off
user@T:~# ethtool --offload eth1 lro off
{% endhighlight %}

		NOTA: Si no puedes cambiar alguno de los parámetros, considera que es posible que ya este apagado.
		      Ejecuta `sudo ethtool --show-offload [interface]` para averiguarlo.

## Jool

Esta es la sintaxis para insertar Jool SIIT en el kernel:<br />
(Requieres permiso de administración)

	user@T:~# modprobe jool_siit \
		[pool6=<IPv6 prefix>] \
		[blacklist=<IPv4 prefixes>] \
		[pool6791=<IPv4 prefixes>] \
		[disabled]

Los parámetros válidos son:

- `pool6` (abreviación de "Pool de IPv6") es el prefijo que el mecanismo de traducción estará adjuntando y removiendo de las direcciones de los paquetes. Este podría ser opcional, porque quizá estas planeando usar EAM.

- `blacklist` representa direcciones IPv4 que Jool **no** va a traducir usando el prefijo pool6, por lo que esto no afecta en la traducción EAM. Puedes insertar hasta cinco prefijos separados por coma durante un modprobe. Si necesitas más, utiliza la [Herramienta de Configuración de Jool](esp-usr-flags-blacklist.html).

- `pool6791` es un pool IPv4 secundario que se utiliza cuando [no hay una conexión directa entre uno o varios nodos y el traductor](esp-misc-rfc6791.html). Si este pool está vacío, Jool enviará la dirección propia de su nodo hacia el nodo destino. Puedes insertar hasta cinco prefijos `pool6791` separados por coma durante un modprobe. Si necesitas más, utiliza la [Herramienta de Configuración de Jool](esp-usr-flags-pool6791.html).

- `disabled` inicia Jool en modo inactivo. Si estás utilizando el configurador, puedes usar esta opción para asegurarte de que has terminado de configurar antes de que tu tráfico empiece a ser traducido.
Si no está presente, Jool empieza a traducir el tráfico de inmediato.

Lo siguiente es sufciente para nuestra red de ejemplo.

	user@T:~# modprobe jool_siit pool6=2001:db8::/96

Eso significa que: "La representación IPv6 de cualquier dirección IPv4 va a ser `2001:db8::<IPv4 address>`."

## Pruebas

### `Conectividad de IPv4 a IPv6`

Haz un ping a _A_ desde _V_ de esta forma:

{% highlight bash %}
user@V:~$ ping 198.51.100.8
PING 198.51.100.8 (198.51.100.8) 56(84) bytes of data.
64 bytes from 198.51.100.8: icmp_seq=1 ttl=63 time=7.45 ms
64 bytes from 198.51.100.8: icmp_seq=2 ttl=63 time=1.64 ms
64 bytes from 198.51.100.8: icmp_seq=3 ttl=63 time=4.22 ms
64 bytes from 198.51.100.8: icmp_seq=4 ttl=63 time=2.32 ms
^C
--- 198.51.100.8 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3006ms
rtt min/avg/max/mdev = 1.649/3.914/7.450/2.249 ms
{% endhighlight %}

### `Conectividad de IPv6 a IPv4`

Haz un ping a _V_ desde _A_:

{% highlight bash %}
user@A:~$ ping6 2001:db8::192.0.2.16
PING 2001:db8::192.0.2.16(2001:db8::c000:210) 56 data bytes
64 bytes from 2001:db8::c000:210: icmp_seq=1 ttl=63 time=3.57 ms
64 bytes from 2001:db8::c000:210: icmp_seq=2 ttl=63 time=10.5 ms
64 bytes from 2001:db8::c000:210: icmp_seq=3 ttl=63 time=1.38 ms
64 bytes from 2001:db8::c000:210: icmp_seq=4 ttl=63 time=2.63 ms
^C
--- 2001:db8::192.0.2.16 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3003ms
rtt min/avg/max/mdev = 1.384/4.529/10.522/3.546 ms
{% endhighlight %}

### `Conectividad a un Web Server en IPv4`

Agrega un servidor en _X_ y accesalo desde _D_:

![Figura 1 - IPv4 TCP desde un nodo IPv6](images/run-vanilla-firefox-4to6.png)

### `Conectividad a un Web Server en IPv6`

Agrega un servidor en _C_ y haz una solicitud desde _W_:

![Figure 2 - IPv6 TCP desde un nodo IPv4](images/run-vanilla-firefox-6to4.png)

Si algo no funciona, consulta el [FAQ](esp-misc-faq.html).

## Deteniendo Jool

Para detener Jool, revierte el modprobe usando solamente el parámetro `-r`:

{% highlight bash %}
user@T:~# modprobe -r jool_siit
{% endhighlight %}

## Lecturas adicionales

Si quieres profundizar te recomedamos leer:

1. El [argumento `pool6791`](esp-usr-flags-pool6791.html) y su [uso](esp-misc-rfc6791.html).
2. Por favor, lee acerca de [problemas con MTUs](esp-misc-mtu.html) antes de seleccionar alguno.
3. Si te interesa EAM, dirigete al [segundo ejemplo](esp-mod-run-eam.html).
4. Si te interesa Stateful NAT64, dirigete al [tercer ejemplo](esp-mod-run-stateful.html).
5. El [documento de DNS64](esp-op-dns64.html) te dirá como configurar un DNS64 para hacer transparente el uso de dirección-prefijo a los usuarios.
