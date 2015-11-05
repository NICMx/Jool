---
language: es
layout: default
category: Documentation
title: Stateful NAT64 - Ejemplo de uso
---

[Documentación](documentation.html) > [Ejemplos de uso](documentation.html#ejemplos-de-uso) > Stateful NAT64

# Stateful NAT64: Ejemplo de Uso

## Índice

1. [Introducción](#introduccin)
2. [Red de ejemplo](#red-de-ejemplo)
	1. [Configuración de Nodos en IPv6](#configuracin-de-nodos-en-ipv6)
	2. [Configuración de Nodos en IPv4](#configuracin-de-nodos-en-ipv4)
	3. [Configuración del Nodo Traductor](#configuracin-del-nodo-traductor)
3. [Jool](#jool)
4. [Pruebas](#pruebas)
	1. [Conectividad de IPv6 a IPv4](#conectividad-de-ipv6-a-ipv4)<br />
	2. [Conectividad a un Web Server en IPv4](#conectividad-a-un-web-server-en-ipv4)
5. [Deteniendo a Jool](#deteniendo-a-jool)
6. [Lecturas adicionales](#lecturas-adicionales)


## Introducción

Este documento explica cómo ejecutar Jool en modo NAT64. Si no tiene nociones de este tipo de traducción consulte [el resumen](intro-xlat.html#stateful-nat64).

Solo es necesaria una [instalación exitosa del módulo del kernel](install-mod.html). El configurador no es requerido en esta ejecución básica.

## Red de ejemplo

![Figura 1 - Red de ejemplo](../images/network/stateful.svg)

Notas:

1. Solamente _A_, _V_ y _T_ son necesarios.
2. Para simplificar, se asumirá que todos los nodos son Linux. En realidad, solamente _T_ necesita serlo.
3. Por simplicidad, se configurará la red estáticamente, mediante el comando `ip`, y (para que la red 203.0.113.0/24 sea alcanzable) tráfico desconocido de la red IPv6 se enrutará hacia _T_. Todo esto puede realizarse de otras maneras si se desea.

### Configuración de Nodos en IPv6

Ejecute la siguiente secuencia de comandos en los nodos _A_-_E_:

{% highlight bash %}
user@A:~# service network-manager stop
user@A:~# /sbin/ip link set eth0 up
user@A:~# # Reemplazar "::8" dependiendo del nodo donde se estén insertando estos comandos.
user@A:~# /sbin/ip address add 2001:db8::8/96 dev eth0
user@A:~# /sbin/ip route add default via 2001:db8::1
{% endhighlight %}

### Configuración de Nodos en IPv4

Ejecute la siguiente secuencia de comandos para los nodos _V_-_Z_:

{% highlight bash %}
user@V:~# service network-manager stop
user@V:~# /sbin/ip link set eth0 up
user@V:~# # Reemplazar ".16" dependiendo del nodo donde se estén insertando estos comandos.
user@V:~# /sbin/ip address add 203.0.113.16/24 dev eth0
{% endhighlight %}

Estos nodos no necesitan una ruta por defecto, y es porque se encuentran en la misma red que _T_. El NAT64 enmascara a _A_-_E_ utilizando 203.0.113.2, de modo que _V_-_Z_ piensan que están hablando directamente con _T_.

### Configuración del Nodo Traductor

Para el Nodo _T_, ejecute la siguiente secuencia de comandos:

{% highlight bash %}
user@T:~# service network-manager stop
user@T:~# 
user@T:~# /sbin/ip link set eth0 up
user@T:~# /sbin/ip address add 2001:db8::1/96 dev eth0
user@T:~# 
user@T:~# /sbin/ip link set eth1 up
user@T:~# /sbin/ip address add 203.0.113.1/24 dev eth1
user@T:~# 
user@T:~# sysctl -w net.ipv4.conf.all.forwarding=1
user@T:~# sysctl -w net.ipv6.conf.all.forwarding=1
user@T:~# ethtool --offload eth0 gro off
user@T:~# ethtool --offload eth0 lro off
user@T:~# ethtool --offload eth1 gro off
user@T:~# ethtool --offload eth1 lro off
{% endhighlight %}

Recuerde que quizá quiera asegurarse de que _T_ puede comunicarse con el resto de los nodos antes de continuar.

## Jool

Esta es la sintaxis para insertar a NAT64 Jool en el kernel:

	user@T:~# /sbin/modprobe jool \
			[pool6=<IPv6 prefix>] \
			[pool4=<IPv4 prefixes>] \
			[disabled]

Ver [argumentos de `jool`](modprobe-nat64.html) para encontrar una descripción de cada uno. En este caso:

	user@T:~# /sbin/modprobe jool pool6=64:ff9b::/96

Jool va a agregar y remover el prefijo `64:ff9b::/96`.

> ![Nota](../images/bulb.svg) No se utilizó el argumento `pool4`, de modo que Jool va a enmascarar paquetes usando los puertos superiores de la dirección 203.0.113.1. A menos que se tengan pocos clientes de IPv6, esto probablemente no es lo que se desea. Ver [`pool4`](pool4.html) para detalles sobre cómo afinar esto.

## Pruebas

Si algo no funciona, el [FAQ](faq.html) puede ser de ayuda.

### Conectividad de IPv6 a IPv4

Contactar a _V_ desde _C_:

{% highlight bash %}
user@C:~$ ping6 64:ff9b::203.0.113.16
PING 64:ff9b::192.0.2.16(64:ff9b::c000:210) 56 data bytes
64 bytes from 64:ff9b::cb00:7110: icmp_seq=1 ttl=63 time=1.13 ms
64 bytes from 64:ff9b::cb00:7110: icmp_seq=2 ttl=63 time=4.48 ms
64 bytes from 64:ff9b::cb00:7110: icmp_seq=3 ttl=63 time=15.6 ms
64 bytes from 64:ff9b::cb00:7110: icmp_seq=4 ttl=63 time=4.89 ms
^C
--- 64:ff9b::203.0.113.16 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 1.136/6.528/15.603/5.438 ms
{% endhighlight %}

### Conectividad a un Web Server en IPv4

Agregar un servidor en _Z_ y accesarlo desde _A_:

![Figura 1 - IPv4 TCP desde un nodo IPv6](../images/run-stateful-firefox-4to6.png)

> ![Nota](../images/bulb.svg) Obviamente, los usuarios no deberían estar conscientes de direcciones IP, y menos aún saber que necesitan agregar un prefijo cuando necesitan hablar con IPv4. [DNS64](dns64.html) puede usarse para hacer el hack transparente para los usuarios.

> ![Nota](../images/bulb.svg) Dado que un NAT64 es stateful, solamente es posible correr pruebas iniciadas desde IPv6 de momento. Ver [redireccionamiento de puertos](bib.html) si la inversa es relevante.

## Deteniendo a Jool

Para detener a Jool, emplee de nuevo el comando modprobe usando el parámetro `-r`:

{% highlight bash %}
user@T:~# /sbin/modprobe -r jool
{% endhighlight %}

## Lecturas adicionales

Interconexiones más complejas entre redes pueden requerir se que consideren las [notas sobre MTUs](mtu.html).

