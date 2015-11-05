---
language: es
layout: default
category: Documentation
title: SIIT - Ejemplo básico
---

[Documentación](documentation.html) > [Ejemplos de uso](documentation.html#ejemplos-de-uso) > SIIT

# SIIT: Ejemplo de Uso

## Índice

1. [Introducción](#introduccin)
2. [Red de ejemplo](#red-de-ejemplo)
	1. [Configuración de Nodos en IPv6](#configuracin-de-nodos-en-ipv6)
	2. [Configuración de Nodos en IPv4](#configuracin-de-nodos-en-ipv4)
	3. [Configuración del Nodo Traductor](#configuracin-del-nodo-traductor)
3. [Jool](#jool)
4. [Pruebas](#pruebas)
	1. [Conectividad de IPv4 a IPv6](#conectividad-de-ipv4-a-ipv6)
	2. [Conectividad de IPv6 a IPv4](#conectividad-de-ipv6-a-ipv4)
	3. [Conectividad a un Web Server en IPv4](#conectividad-a-un-web-server-en-ipv4)
	4. [Conectividad a un Web Server en IPv6](#conectividad-a-un-web-server-en-ipv6)
5. [Deteniendo a Jool](#deteniendo-a-jool)
6. [Lecturas adicionales](#lecturas-adicionales)

## Introducción

Este documento explica cómo ejecutar a Jool en modo SIIT básico. Se puede encontrar una explicación de este tipo de traducción [aquí](intro-xlat.html#siit-tradicional).

Solamente se necesita una instalación exitosa del [módulo del kernel](install-mod.html) para seguir este documento. La aplicación de espacio de usuario no es aún necesaria.

> ![Note](../images/bulb.svg) Jool no está condicionado a usar interfaces físicas de tipo _ethX_; puede usar alternativamente otros tipos de interfaces, incluyendo las que desembocan en (o pertenecen a) máquinas virtuales.

## Red de ejemplo

![Figura 1 - Red de ejemplo Vanilla](../images/network/vanilla.svg "Figura 1 - Red de ejemplo Vanilla")

Solamente los nodos _A_, _T_ y _V_ son necesarios. El resto son muy similares y aparecen solo con propósitos ilustrativos.

Este tutorial asumirá que se tiene el bloque 198.51.100.0/24 para distribuir entre los nodos IPv6.

Jool requiere que _T_ tenga instalado Linux. El resto de los nodos puede tener cualquier otro sistema operativo, siempre y cuando implementen los protocolos relevantes (IPv6, IPv4, TCP, UDP e ICMP) correctamente.

Sin embargo, para efectos de simplicidad, los comandos aquí expuestos asumen que todos los nodos tienen instalado Linux y que todo está siendo configurado estáticamente usando el tradicional comando `ip`.

Para aclarar, el comando `service network-manager stop` sirve para apagar el administrador de red de modo que `ip` tenga control exclusivo sobre las interfaces. En distribuciones diferentes a Ubuntu, puede ser necesario modificar este comando.

Para simplificar ruteo, todo el tráfico será dirigido por defecto hacia _T_.

### Configuración de Nodos en IPv6

Para los nodos de _A_ a _E_, ejecute la siguiente secuencia de comandos:

{% highlight bash %}
user@A:~# service network-manager stop
user@A:~# ip link set eth0 up
user@A:~# # Reemplazar ".8" dependiendo del nodo donde se estén insertando estos comandos.
user@A:~# ip addr add 2001:db8::198.51.100.8/120 dev eth0
user@A:~# ip route add default via 2001:db8::198.51.100.1
{% endhighlight %}


### Configuración de Nodos en IPv4

Para los nodos de _V_ a _Z_, ejecute la siguiente secuencia de comandos:

{% highlight bash %}
user@V:~# service network-manager stop
user@V:~# ip link set eth0 up
user@V:~# # Reemplazar ".16" dependiendo del nodo donde se estén insertando estos comandos.
user@V:~# ip addr add 192.0.2.16/24 dev eth0
user@V:~# ip route add default via 192.0.2.1
{% endhighlight %}

### Configuración del Nodo Traductor

Ejecute la siguiente secuencia de comandos en _T_:

{% highlight bash %}
user@T:~# service network-manager stop
user@T:~# 
user@T:~# ip link set eth0 up
user@T:~# ip addr add 2001:db8::198.51.100.1/120 dev eth0
user@T:~# 
user@T:~# ip link set eth1 up
user@T:~# ip addr add 192.0.2.1/24 dev eth1
{% endhighlight %}

Los nodos _A_-_E_ no pueden todavía interactuar con _V_-_Z_ porque _T_ no es un traductor aún. Se recomienda validar la comunicacion entre nodos adyacentes utilizando `ping` y `ping6` antes de continuar.

El siguiente paso es informar a Linux que se desea utilizar los stacks de red con propósitos de forwarding (ie. _T_ cumple funciones de enrutador):

{% highlight bash %}
user@T:~# sysctl -w net.ipv4.conf.all.forwarding=1
user@T:~# sysctl -w net.ipv6.conf.all.forwarding=1
{% endhighlight %}

> ![Nota](../images/bulb.svg) Estos sysctls tienen sentido conceptualmente, pero Jool en realidad no depende de ellos actualmente.
> 
> Lo que pasa es que si se dejan desactivados, kernels 3.5 e inferiores van a tirar cierto tráfico de ICMP importante. Este problema no existe en Linux 3.6 en adelante.
> 
> [No se sabe si el comportamiento correcto es el de Linux antiguo o el del nuevo](https://github.com/NICMx/NAT64/issues/170#issuecomment-141507174). Por otro lado, Jool 4.0 probablemente va a requerir forwarding, de modo que se recomienda incluir los sysctls aunque no sean todavía necesarios.

También se requiere asegurar que [offloads de recepción estén apagados](offloads.html) en todas las interfaces de _T_ relevantes.

{% highlight bash %}
user@T:~# ethtool --offload eth0 gro off
user@T:~# ethtool --offload eth0 lro off
user@T:~# ethtool --offload eth1 gro off
user@T:~# ethtool --offload eth1 lro off
{% endhighlight %}

Si no es posible cambiar alguno de los parámetros, probablemente es porque [ya está apagado](offloads.html#cmo-deshacerse-de-offloads-de-recepcin).

## Jool

Esta es la sintaxis para insertar a Jool SIIT en el kernel:

	user@T:~# /sbin/modprobe jool_siit \
			[pool6=<IPv6 prefix>] \
			[blacklist=<IPv4 prefixes>] \
			[pool6791=<IPv4 prefixes>] \
			[disabled]

Ver [argumentos de `jool_siit`](modprobe-siit.html) para encontrar una descripción de cada uno. Lo siguiente es suficiente para la red de ejemplo:

	user@T:~# modprobe jool_siit pool6=2001:db8::/96

Eso significa que la representación IPv6 de cualquier dirección IPv4 va a ser `2001:db8::<Dirección de IPv4>`.

## Pruebas

Si algo no funciona, el [FAQ](faq.html) puede ser de ayuda.

### Conectividad de IPv4 a IPv6

_V_ puede hacer ping hacia _A_ de la siguiente forma:

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

### Conectividad de IPv6 a IPv4

Para contactar a _V_ desde _A_:

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

### Conectividad a un Web Server en IPv4

Levantar un servidor en _X_ y accesarlo desde _D_:

![Figura 1 - IPv4 TCP desde un nodo IPv6](../images/run-vanilla-firefox-4to6.png)

### Conectividad a un Web Server en IPv6

Agregar un servidor en en _C_ y accesarlo desde _W_:

![Figure 2 - IPv6 TCP desde un nodo IPv4](../images/run-vanilla-firefox-6to4.png)

## Deteniendo a Jool

`modprobe` también es capaz de quitar módulos. Usar `-r` para indicarlo:

{% highlight bash %}
user@T:~# modprobe -r jool_siit
{% endhighlight %}

## Lecturas adicionales

Interconexiones más complejas entre redes pueden requerir se que consideren las [notas sobre MTUs](mtu.html).

