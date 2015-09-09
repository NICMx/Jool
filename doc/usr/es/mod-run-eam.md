---
language: es
layout: default
category: Documentation
title: SIIT-EAM - Ejemplo de uso
---

[Documentación](documentation.html) > [Ejemplos de uso](documentation.html#ejemplos-de-uso) > SIIT + EAM

# EAM: Ejemplo de Uso

## Índice

1. [Introducción](#introduccin)
2. [Red de ejemplo](#red-de-ejemplo)<br />
	a) [Configuración de Nodos en IPv6](#configuracin-de-nodos-en-ipv6)<br />
	b) [Configuración de Nodos en IPv4](#configuracin-de-nodos-en-ipv4)<br />
	c) [Configuración del Nodo Traductor](#configuracin-del-nodo-traductor)
3. [Jool](#jool)
4. [Pruebas](#pruebas)<br />
	a) [Conectividad de IPv6 a IPv4](#conectividad-de-ipv6-a-ipv4)<br />
	b) [Conectividad de IPv4 a IPv6](#conectividad-de-ipv4-a-ipv6)<br />
	c) [Conectividad a un Web Server en IPv4](#conectividad-a-un-web-server-en-ipv4)<br />
	d) [Conectividad a un Web Server en IPv6](#conectividad-a-un-web-server-en-ipv6)
5. [Deteniendo Jool](#deteniendo-jool)
6. [Lecturas adicionales](#lecturas-adicionales)

## Introducción

Este documento explica cómo ejecutar Jool en modo EAM. Si no tienes nociones de este tipo de traducción ingresa a [SIIT-EAM ](intro-nat64.html#siit-con-eam). 

Más que un "modo" es simplemente proveer a SIIT con registros en la tabla de Direcciones de Mapeo Explícito. Obtenen más detalles sobre [ésta](eamt.html). 

Similar al SIIT Tradicional, solo necesitas una instalación exitosa de ambos: del [Servidor Jool](mod-install.html) **y** del [Configurador para SIIT](usr-install.html).

## Red de ejemplo

![Figura 1 - Red de ejemplo](../images/network/eam.svg)

Aquí también, son válidas y aplican las observaciones mencionadas de la [sección Red de Ejemplo para SIIT](mod-run-vanilla.html#red-de-ejemplo). Resumiéndolas, tenemos que:

- Al menos necesitarás tres nodos: _A_, _V_ y _T_.
- Usa el bloque de direcciones 198.51.100.8/29 para referenciar a tus nodos de IPv6 sobre IPv4.
- Jool requiere Linux, los otros Nodos no necesariamente.
- Para este tutorial, consideraremos que: a)todos están en Linux, b)la configuración de red se hará manualmente, c) todo el tráfico será redirigido por defecto hacia _T_.

### Configuración de Nodos en IPv6

Para los nodos de _A_ a _E_, ejecuta la siguiente secuencia de comandos con permisos de administrador:

{% highlight bash %}
user@A:~# service network-manager stop
user@A:~# /sbin/ip link set eth0 up
user@A:~# # Replace "::8" dependiendo en que nodo estés.
user@A:~# /sbin/ip addr add 2001:db8:6::8/96 dev eth0
user@A:~# /sbin/ip route add default via 2001:db8:6::1
{% endhighlight %}

### Configuración de Nodos en IPv4

Para los nodos de _V_ a _Z_, ejecuta la siguiente secuencia de comandos con permisos de administrador:

{% highlight bash %}
user@V:~# service network-manager stop
user@V:~# /sbin/ip link set eth0 up
user@V:~# # Replace ".16" dependiendo en que nodo estés.
user@V:~# /sbin/ip addr add 192.0.2.16/24 dev eth0
user@V:~# /sbin/ip route add default via 192.0.2.1
{% endhighlight %}

### Configuración del Nodo Traductor

Para el Nodo _T_, ejecuta la siguiente secuencia de comandos con permisos de administrador:

{% highlight bash %}
user@T:~# service network-manager stop
user@T:~# 
user@T:~# /sbin/ip link set eth0 up
user@T:~# /sbin/ip addr add 2001:db8:6::1/96 dev eth0
user@T:~# 
user@T:~# /sbin/ip link set eth1 up
user@T:~# /sbin/ip addr add 192.0.2.1/24 dev eth1
user@T:~# 
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

Hasta aquí, no hemos convertido a _T_ en un traductor todavía; pero, quizá quieras asegurarte de que _T_ puede comunicarse con todos los nodos antes de continuar.

## Jool

Recuerda, la sintaxis para insertar Jool SIIT en el kernel es:<br />
(Requieres permiso de administración)

	user@T:~# modprobe jool_siit [pool6=<IPv6 prefix>] [blacklist=<IPv4 prefixes>] [pool6791=<IPv4 prefixes>] [disabled]
	
Para configurar nuestra red de ejemplo, ejecuta como administrador:

{% highlight bash %}
user@T:~# /sbin/modprobe jool_siit disabled
user@T:~# jool_siit --eamt --add 2001:db8:6::/120 198.51.100.0/24
user@T:~# jool_siit --eamt --add 2001:db8:4::/120 192.0.2.0/24
user@T:~# jool_siit --enable
{% endhighlight %}

A diferencia de `pool6`, no es práctico insertar la tabla EAM completa en un solo comando, asi que instruimos a Jool para que inicie deshabilitado. Luego insertamos los registros de la tabla EAM, uno por uno, utilizando la [Herramienta de Configuración](usr-flags-eamt.html). Cuando la tabla está completa, le decimos a Jool que puede empezar a traducir trafico mediante la opción de [`--enable`](usr-flags-global.html#enable---disable).

De hecho utilizar `disabled` y `--enable` no es necesario; Jool va a deducir naturalmente que no puede traducir tráfico hasta que la tabla EAM y/o pool6 sean llenados. La razón por la cual Jool fue "forzado" a permanecer deshabilitado hasta que la tabla estuviera completa fue para que no hubiera un periodo de tiempo donde el tráfico estuviera siendo traducido inconsistentemente debido a una tabla incompleta.

Y de nuevo, el prefijo IPv6 y la tabla EAM no son modos de operación exclusivos. Jool siempre va a tratar de traducir una dirección utilizando EAM, y si eso falla, retrocederá a utilizar el prefijo. Si quieres esto, agrega `pool6` durante el `modprobe`.

## Pruebas

### Conectividad de IPv6 a IPv4

Haz un ping a _V_ desde _A_:

{% highlight bash %}
user@A:~$ ping6 2001:db8:4::10 # Reminder: hex 10 = dec 16.
PING 2001:db8:4::10(2001:db8:4::10) 56 data bytes
64 bytes from 2001:db8:4::10: icmp_seq=1 ttl=63 time=2.95 ms
64 bytes from 2001:db8:4::10: icmp_seq=2 ttl=63 time=2.79 ms
64 bytes from 2001:db8:4::10: icmp_seq=3 ttl=63 time=4.13 ms
64 bytes from 2001:db8:4::10: icmp_seq=4 ttl=63 time=3.60 ms
^C
--- 2001:db8:4::10 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3003ms
rtt min/avg/max/mdev = 2.790/3.370/4.131/0.533 ms
{% endhighlight %}

### Conectividad de IPv4 a IPv6

Haz un ping a _A_ desde _V_ de esta forma:

{% highlight bash %}
user@V:~$ ping 198.51.100.8
PING 198.51.100.8 (198.51.100.8) 56(84) bytes of data.
64 bytes from 198.51.100.8: icmp_seq=1 ttl=63 time=5.04 ms
64 bytes from 198.51.100.8: icmp_seq=2 ttl=63 time=2.55 ms
64 bytes from 198.51.100.8: icmp_seq=3 ttl=63 time=1.93 ms
64 bytes from 198.51.100.8: icmp_seq=4 ttl=63 time=2.47 ms
^C
--- 198.51.100.8 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 1.930/3.001/5.042/1.204 ms
{% endhighlight %}

### Conectividad a un Web Server en IPv4

Agrega un servidor en _Y_ y accesalo desde _D_:

![Figura 1 - IPv4 TCP desde un nodo IPv6](../images/run-eam-firefox-4to6.png)

### Conectividad a un Web Server en IPv6

Agrega un servidor en _B_ y haz una solicitud desde _X_:

![Figura 2 - IPv6 TCP desde un nodo IPv4](../images/run-vanilla-firefox-6to4.png)

Si algo no funciona, consulta el [FAQ](faq.html).

## Deteniendo Jool

Para detener Jool, emplea de nuevo el comando modprobe usando el parámetro `-r`:

{% highlight bash %}
user@T:~# modprobe -r jool_siit
{% endhighlight %}

## Lecturas adicionales

1. Por favor, lee acerca de [problemas con MTUs](mtu.html) antes de seleccionar alguno.
2. Si te interesa Stateful NAT64, dirigete al [tercer ejemplo](mod-run-stateful.html).
