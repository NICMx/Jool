---
layout: documentation
title: Documentación - Ejemplo básico de SIIT 
---

[Documentación](esp-doc-index.html) > [Ejemplos de uso](esp-doc-index.html#ejemplos-de-uso) > SIIT

# Ejecución de SIIT

## Índice

1. [Introducción](#introduccion)
2. [Red de ejemplo](#red-de-ejemplo)
3. [Jool](#jool)
4. [Pruebas](#pruebas)
5. [Deteniendo Jool](#deteniendo-jool)
6. [Lecturas adicionales](#lecturas-adicionales)

## Introducción

Este documento explica como ejecutar Jool en [modo SIIT](esp-intro-nat64.html#siit-tradicional). Ingresa al enlace para obtener más detalles sobre que esperar de éste tutorial.

En cuanto a software, solo se necesita una [instalación exitosa del modulo de kernel de Jool](esp-mod-install.html). La aplicación de espacio de usuario queda fuera del rango del proposito de éste documento.

En caso de que te preguntes, puedes darle seguimiento a estos tutoriales utilizando máquinas virtuales o tipos alternos de interfaces (Jool no esta casado con interfaces fisicas "_ethX_").

## Red de ejemplo

No necesitas todos los nodos que se muestran en el diagrama para dar seguimiento; puedes lograrlo con sólo _A_, _T_ y _V_; el resto son muy similares a _A_ y _V_ y son mostrados para propósitos illustrativos.

![Figure 1 - Red de ejemplo](images/network/vanilla.svg)


Pretenderemos que tengo un bloque de direcciones 198.51.100.8/29 para distribuirlo entre mis nodos IPv6.

Jool requiere que _T_ tenga instalado Linux. El resto puede tener lo que ustedes quieran, siempre y cuando implemente el protocolo de la red a la que estan conectados. Tambien, se tiene la libertad de configurar la red utilizando el administrador que se prefiera.

Sin embargo para efectos de simplicidad, los ejemplos en la parte de abajo asumen que todos los nodos tienen instalado Linux y que todo esta siendo configurado estáticamente usando el bien-conocido comando `ip` (y compañia). Dependiendo de tu distribución, el kilometraje puede variar en cuanto a la forma de como quitar del camino al administrador de red (asumiendo que eso es lo que quieres). Sólo para dejar en claro, el punto de `service network-manager stop` es para adquirir control sobre las direcciones y rutas de tu interfáz (de otra forma los comandos `ip` pudieran no tener efecto).

Tambien para simplificar, el ruteo será reducido a dirigir por defecto todo el tráfico desconocido hacia _T_. Date cuenta de que aparte de esto no hay nada extraño en la configuración de ningun nodo.

Esto es, nodos de _A_ a _E_:

{% highlight bash %}
user@A:~# service network-manager stop
user@A:~# /sbin/ip link set eth0 up
user@A:~# # Replace ".8" depending on which node you're on.
user@A:~# /sbin/ip addr add 2001:db8::198.51.100.8/120 dev eth0
user@A:~# /sbin/ip route add default via 2001:db8::198.51.100.1
{% endhighlight %}

Nodos de _V_ a _Z_:

{% highlight bash %}
user@V:~# service network-manager stop
user@V:~# /sbin/ip link set eth0 up
user@V:~# # Replace ".16" depending on which node you're on.
user@V:~# /sbin/ip addr add 192.0.2.16/24 dev eth0
user@V:~# /sbin/ip route add default via 192.0.2.1
{% endhighlight %}

Nodo _T_:

{% highlight bash %}
user@T:~# service network-manager stop
user@T:~# 
user@T:~# /sbin/ip link set eth0 up
user@T:~# /sbin/ip addr add 2001:db8::198.51.100.1/120 dev eth0
user@T:~# 
user@T:~# /sbin/ip link set eth1 up
user@T:~# /sbin/ip addr add 192.0.2.1/24 dev eth1
user@T:~# 
user@T:~# sysctl -w net.ipv4.conf.all.forwarding=1
user@T:~# sysctl -w net.ipv6.conf.all.forwarding=1
{% endhighlight %}

Ya que no hemos convertido a _T_ en un traductor todavia, los nodos desde _A_ hasta _E_ no pueden interactuar todavía con los nodos _V_ hasta _Z_, pero quizá quieras asegurarte de que _T_ puede hacer ping a todos antes de continuar.

La única precaución que ocupas tener en mente antes de incrustar Jool (o lidiar con IPv6 en general) es que el habilitar forwarding en Linux no te libera automáticamente de offloads. Offloading is a _leaf_ node feature, otherwise a bug, and therefore it's important to turn it off on all routers. [Lee este documento](esp-misc-offloading.html) si quieres detalles.

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

(Si se queja de que no puede cambiar algo, toma en cuenta de que ya puede encontrarse apagado; ejecuta `sudo ethtool --show-offload [interface]` para averiguarlo.)

## Jool

Esta es la sintaxis de incrustamiento:

	user@T:~# /sbin/modprobe jool_siit \
		[pool6=<IPv6 prefix>] \
		[blacklist=<IPv4 prefixes>] \
		[pool6791=<IPv4 prefixes>] \
		[disabled]

Estos son los argumentos:

- `pool6` (abreviación de "IPv6 pool") es el prefijo que el mecanismo de traducción estará adjuntando y removiendo de las direcciones de los paquetes.  

Esto es opcional por que quizá quieras usar la tabla EAM.

- `blacklist` representa direcciones IPv4 que Jool **no** va a traducir usando el prefijo pool6 (ie. esto no afecta la traducción EAMT).  
Puedes insertar hasta cinco prefijos `blacklist` separados por coma durante un modprobe. Si necesitas mas, utiliza la [aplicación de espacio de usuario](esp-usr-flags-blacklist.html).
- `pool6791` es un pool IPv4 secundario que se utiliza para algo[un poco mas críptico](esp-misc-rfc6791.html). Quizá prefieras leer esta explicación _despues_ de que hayas asimilado los fundamentos de este recorrido.  
Si este pool está vacío, Jool retrocederá a enviar la dirección propia de su nodo hacia el nodo de destino.  
Puedes insertar hasta cinco prefijos `pool6791` separados por coma durante un modprobe. Si necesitas mas, utiliza la [aplicación de espacio de usuario](esp-usr-flags-pool6791.html).
- `disabled` inicia Jool en modo inactivo. Si estas utilizando la aplicación de espacio de usuario, puedes usarla para asegurarte de que has terminado de configurar antes de que tu tráfico empiece a ser traducido. El recorrido por EAM ejemplifica su uso.  
Si no está presente, Jool empieza a traducir el tráfico de inmediato.

Lo siguiente es sufciente para nuestra red de ejemplo.

	user@T:~# /sbin/modprobe jool_siit pool6=2001:db8::/96

Eso significa que la representación IPv6 de cualquier dirección IPv4 va a ser `2001:db8::<IPv4 address>`. Ver ejemplos abajo.

## Pruebas

Si algo no funciona, try the [FAQ](esp-misc-faq.html).

Intenta hacer un ping a _A_ desde _V_ de esta forma:

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

Despues has un ping a _V_ desde _A_:

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

Que te pareceria agregar un servidor en _X_ y accesarlo desde _D_:

![Figure 1 - IPv6 TCP from an IPv4 node](images/run-vanilla-firefox-4to6.png)

Y despues quizá otro en _C_ y hacer una solicitud desde _W_:

![Figure 2 - IPv4 TCP from an IPv6 node](images/run-vanilla-firefox-6to4.png)

## Deteniendo Jool

Para detener Jool, revierte el modprobe usando el parámetro `-r`:

{% highlight bash %}
user@T:~# /sbin/modprobe -r jool_siit
{% endhighlight %}

## Lecturas adicionales

Aqui tienes algunas lecturas adicionales por si gustas profundizar:

- El [argumento `pool6791`](esp-usr-flags-pool6791.html) y su [gimmic](esp-misc-rfc6791.html).
- Por favor considera los [detalles de MTU](esp-misc-mtu.html) antes de liberar.
- Si te interesa EAM, dirigete al [segundo ejemplo](esp-mod-run-eam.html).
- Si te interesa stateful NAT64, dirigete al [tercer ejemplo](esp-mod-run-stateful.html).
- El [documento de DNS64](esp-op-dns64.html) te dirá como hacer el hack prefijo-dirección transparente a los usuarios.
