---
layout: documentation
title: Documentación - SIIT-EAM: Ejemplo de uso
---

[Documentación](esp-doc-index.html) > [Ejemplos de uso](esp-doc-index.html#ejemplos-de-uso) > SIIT + EAM

# EAM: Ejemplo de Uso

## Índice

1. [Introducción](#introduccion)
2. [Red de ejemplo](#red-de-ejemplo)
3. [Jool](#jool)
4. [Pruebas](#pruebas)
5. [Deteniendo Jool](#deteniendo-jool)
6. [Lecturas adicionales](#lecturas-adicionales)

## Introducción

Este documento explica cómo ejecutar Jool en [modo EAM](esp-intro-nat64.html#siit-con-eam). Ingresa al enlace para obtener más detalles sobre qué esperar de éste tutorial. También mira [el resume del EAMT draft](esp-misc-eamt.html) para obtener más detalles de cómo funciona EAMT. SIIT-EAM mas que un "modo" es simplemente proveer a SIIT con registros en la tabla EAM.

El [Modo Stock](esp-mod-run-vanilla.html) es más rapido de configurar y nos gustaría alentarte a que lo aprendas antes,  particularmente por que no voy a desarrollar aqui los pasos que ambos modos tienen en común. En cuanto al software, necesitas una instalación exitosa de ambos del [Servidor Jool](esp-mod-install.html) **y** el [configurador](esp-usr-install.html) para EAM.

## Red de ejemplo

![Figure 1 - Red de ejemplo](images/network/eam.svg)

Todas las observaciones en la [Sección Red de Ejemplo](esp-mod-run-vanilla.html#red-de-ejemplo) del documento previo aplican aquí.

Esto es nodos desde _A_ hasta _E_:

{% highlight bash %}
user@A:~# service network-manager stop
user@A:~# /sbin/ip link set eth0 up
user@A:~# # Replace "::8" dependiendo en que nodo estés.
user@A:~# /sbin/ip addr add 2001:db8:6::8/96 dev eth0
user@A:~# /sbin/ip route add default via 2001:db8:6::1
{% endhighlight %}

Nodos desde _V_ hasta _Z_ tienen exactamente la misma configuración del documento previo.

{% highlight bash %}
user@V:~# service network-manager stop
user@V:~# /sbin/ip link set eth0 up
user@V:~# # Replace ".16" dependiendo en que nodo estés.
user@V:~# /sbin/ip addr add 192.0.2.16/24 dev eth0
user@V:~# /sbin/ip route add default via 192.0.2.1
{% endhighlight %}

El nodo _T_:

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

Recuerda que quizá quieras hacer un cross-ping de _T_ con todo antes de continuar.

## Jool

{% highlight bash %}
user@T:~# /sbin/modprobe jool_siit disabled
user@T:~# jool_siit --eamt --add 2001:db8:6::/120 198.51.100.0/24
user@T:~# jool_siit --eamt --add 2001:db8:4::/120 192.0.2.0/24
user@T:~# jool_siit --enable
{% endhighlight %}

A diferencia de `pool6`, no es práctico insertar la tabla EAM completa en un solo comando, asi que instruimos a Jool para que inicie deshabilitado. Luego insertamos los registros de la tabla EAM, uno por uno, utilizando la [Herramienta de Configuración](esp-usr-flags-eamt.html). Cuando la tabla está completa, le decimos a Jool que puede empezar a traducir trafico[`--enable`](esp-usr-flags-global.html#enable---disable)).

De hecho utilizar `disabled` y `--enable` no es necesario; Jool va a deducir naturalmente que no puede traducir tráfico hasta que la tabla EAM y/o pool6 sean llenados. La razón por la cual Jool fue "forzado" a permanecer deshabilitado hasta que la tabla estuviera completa fue para que no hubiera un periodo de tiempo donde el tráfico estuviera siendo traducido inconsistentemente debido a una tabla incompleta.

Y de nuevo, el prefijo IPv6 y la tabla EAM no son modos de operación exclusivos. Jool siempre va a tratar de traducir una dirección utilizando EAM, y si eso falla, retrocederá a utilizar el prefijo. Si quieres esto, agrega `pool6` durante el `modprobe`.

## Pruebas

Haz ping a _V_ desde _A_ de esta manera:

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

Luego haz ping a _A_ desde _V_:

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

Que te parecería agregar un servidor en _Y_ y accesarlo desde _D_:

![Figure 1 - IPv6 TCP from an IPv4 node](images/run-eam-firefox-4to6.png)

Luegp quizá otro en _B_ y hacer una solicitud desde _X_:

![Figure 2 - IPv4 TCP from an IPv6 node](images/run-eam-firefox-6to4.png)

Si algo no funciona, consulta el [FAQ](esp-misc-faq.html).

## Deteniendo Jool

Igual que en el [ejemplo-previo](esp-mod-run-vanilla.html#deteniendo-jool).

## Lecturas adicionales

- Por favor considera los [detalles de MTU](esp-misc-mtu.html) antes de liberar.
- Stateful NAT64 está [aquí](esp-mod-run-stateful.html).