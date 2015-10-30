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
2. [Red de ejemplo](#red-de-ejemplo)
	1. [Configuración de Nodos en IPv6](#configuracin-de-nodos-en-ipv6)
	2. [Configuración de Nodos en IPv4](#configuracin-de-nodos-en-ipv4)
	3. [Configuración del Nodo Traductor](#configuracin-del-nodo-traductor)
3. [Jool](#jool)
4. [Pruebas](#pruebas)
	1. [Conectividad de IPv6 a IPv4](#conectividad-de-ipv6-a-ipv4)
	2. [Conectividad de IPv4 a IPv6](#conectividad-de-ipv4-a-ipv6)
	3. [Conectividad a un Web Server en IPv4](#conectividad-a-un-web-server-en-ipv4)
	4. [Conectividad a un Web Server en IPv6](#conectividad-a-un-web-server-en-ipv6)
5. [Deteniendo a Jool](#deteniendo-a-jool)
6. [Lecturas adicionales](#lecturas-adicionales)

## Introducción

Este documento explica cómo ejecutar Jool en modo SIIT+EAM. Una introducción a este mecanismo de traducción de direcciones puede encontrarse [aquí](intro-xlat.html#siit-con-eam).

A diferencia del [tutorial anterior](run-vanilla.html), este documento tiene como prerequisito una instalación de tanto el [módulo del kernel](install-mod.html) como de la [aplicación de espacio de usuario](install-usr.html).

## Red de ejemplo

![Figura 1 - Red de ejemplo](../images/network/eam.svg)

Varias observaciones mencionadas en la sección [sección Red de Ejemplo para SIIT](run-vanilla.html#red-de-ejemplo) también aplican aquí:

- Tres nodos son suficientes: _A_, _V_ y _T_.
- Se usará el bloque de direcciones 198.51.100.0/24 para enmascarar a los nodos de IPv6.
- Jool requiere que _T_ sea Linux.
- Este tutorial asume que todos son Linux, la configuración de red se hará manualmente y todo el tráfico será dirigido por defecto hacia _T_.

### Configuración de nodos en IPv6

Ejecute la siguiente secuencia de comandos para los nodos _A_ hasta _E_:

{% highlight bash %}
user@A:~# service network-manager stop
user@A:~# /sbin/ip link set eth0 up
user@A:~# # Reemplazar "::8" dependiendo del nodo donde se estén insertando estos comandos.
user@A:~# /sbin/ip addr add 2001:db8:6::8/96 dev eth0
user@A:~# /sbin/ip route add default via 2001:db8:6::1
{% endhighlight %}

### Configuración de nodos en IPv4

Ejecute la siguiente secuencia de comandos en _V_ hasta _Z_:

{% highlight bash %}
user@V:~# service network-manager stop
user@V:~# /sbin/ip link set eth0 up
user@V:~# # Reemplazar ".16" dependiendo del nodo donde se estén insertando estos comandos.
user@V:~# /sbin/ip addr add 192.0.2.16/24 dev eth0
user@V:~# /sbin/ip route add default via 192.0.2.1
{% endhighlight %}

### Configuración del nodo traductor

Ejecute la siguiente secuencia de comandos en el Nodo _T_:

{% highlight bash %}
user@T:~# service network-manager stop
user@T:~# 
user@T:~# /sbin/ip link set eth0 up
user@T:~# /sbin/ip addr add 2001:db8:6::1/96 dev eth0
user@T:~# 
user@T:~# /sbin/ip link set eth1 up
user@T:~# /sbin/ip addr add 192.0.2.1/24 dev eth1
user@T:~# 
user@T:~# sysctl -w net.ipv4.conf.all.forwarding=1
user@T:~# sysctl -w net.ipv6.conf.all.forwarding=1
user@T:~# ethtool --offload eth0 gro off
user@T:~# ethtool --offload eth0 lro off
user@T:~# ethtool --offload eth1 gro off
user@T:~# ethtool --offload eth1 lro off
{% endhighlight %}

Hasta aquí _T_ no es un traductor todavía. Antes de continuar se recomienda confirmar que nodos adyacentes puedan interactuar entre sí.

## Jool

{% highlight bash %}
user@T:~# /sbin/modprobe jool_siit disabled
user@T:~# jool_siit --eamt --add 2001:db8:6::/120 198.51.100.0/24
user@T:~# jool_siit --eamt --add 2001:db8:4::/120 192.0.2.0/24
user@T:~# jool_siit --enable
{% endhighlight %}

A diferencia de `pool6`, no es práctico insertar la tabla EAM completa en un solo comando, de modo que se inicia a Jool deshabilitado y se insertan los registros de la tabla EAM posteriormente (utilizando la [Aplicación de Configuración](usr-flags-eamt.html)). Cuando la tabla está completa, se le indica a Jool que empiece a traducir tráfico mediante la opción [`--enable`](usr-flags-global.html#enable---disable).

En realidad, utilizar `disabled` y `--enable` no es necesario; Jool va a deducir naturalmente que no puede traducir tráfico hasta que la tabla EAM y/o pool6 tengan elementos. La razón por la cual Jool fue "forzado" a permanecer deshabilitado hasta que la tabla estuviera completa fue para que no hubiera un período de tiempo donde el tráfico estuviera siendo traducido inconsistentemente debido a una tabla incompleta.

Y de nuevo, el prefijo IPv6 y la tabla EAM no son modos de operación exclusivos. Jool siempre va a tratar de traducir direcciones utilizando EAM, y si eso falla, retrocederá a utilizar el prefijo. Si desea esto, agregue `pool6` durante el `modprobe`.

## Pruebas

Si algo no funciona, el [FAQ](faq.html) puede ser de ayuda.

### Conectividad de IPv6 a IPv4

Realizar un ping a _V_ desde _A_:

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

Realizar un ping a _A_ desde _V_:

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

Levantar un servidor en _Y_ y accesarlo desde _D_:

![Figura 1 - IPv4 TCP desde un nodo IPv6](../images/run-eam-firefox-4to6.png)

### Conectividad a un Web Server en IPv6

Levantar un servidor en _B_ y accesarlo desde _X_:

![Figura 2 - IPv6 TCP desde un nodo IPv4](../images/run-vanilla-firefox-6to4.png)

## Deteniendo a Jool

Para detener Jool, emplea de nuevo el comando modprobe usando el parámetro `-r`:

{% highlight bash %}
user@T:~# modprobe -r jool_siit
{% endhighlight %}

## Lecturas adicionales

Interconexiones más complejas entre redes pueden requerir se que consideren las [notas sobre MTUs](mtu.html).

