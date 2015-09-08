---
language: es
layout: default
category: FAQ
title: FAQ/Solución de problemas
---

[Documentación](documentation.html) > [Otros](documentation.html#miscellaneous) > FAQ/Solución de problemas

# FAQ/Solución de problemas

Esto resume problemas con los cuales algunos usuarios se han topado.


## Instalé el módulo de Jool pero no parece estar haciendo nada.

Instalar el módulo del Jool sin argumentos suficientes es legal. Asumirá que intentas terminar de configurar utilizando la Aplicación de espacio de usuario, y se mantendrá inactivo hasta que lo hayas hecho.

Utiliza el parámetro [`--global`](usr-flags-global.html#description) para saber el estado en el que se encuentra Jool:

{% highlight bash %}
$ jool_siit --global
  Status: Disabled
{% endhighlight %}

{% highlight bash %}
$ jool --global
  Status: Disabled
{% endhighlight %}

Los requerimientos mínimos de configuración de SIIT Jool son:

- Un prefijo en el [pool IPv6](usr-flags-pool6.html) **o** por lo menos un registro en la [tabla EAM](usr-flags-eamt.html).
- No debes de haberlo [deshabilitado manualmente](usr-flags-global.html#enable---disable).

Los requerimientos mínimos de configuración de NAT64 Jool son:

- Por lo menos un prefijo en [pool6](usr-flags-pool6.html).
- Por lo menos un(a) prefijo/dirección en [pool4](usr-flags-pool4.html).
- No debes de haberlo [deshabilitado manualmente](usr-flags-global.html#enable---disable).


Si eso no parece ser el problema, trata ver los [logs](#logging.html).

## ¿Qué hago con este mensaje de error? Es horriblemente ambiguo.

Esto sucede si tu terminal no está escuchando mensajes del kernel de severidad "error".

El chiste es que, si se le pide algo a Jool mediante la aplicación de usuario y hay un problema, Jool no regresa la versión amigable del error a la aplicación ([reporte](https://github.com/NICMx/NAT64/issues/169)); en lugar de eso la imprime en los logs. Lo único que recibe la aplicación es un código genérico de Unix, y eso es lo que reporta al usuario.

[Corre `dmesg` o una de sus variantes para consultar los logs](#logging.html), como se muestra en el [reporte](https://github.com/NICMx/NAT64/issues/169).

## Jool es intermitentemente incapaz de traducir tráfico.

Ejecutaste algo como:

{% highlight bash %}
ip addr flush dev eth1
{% endhighlight %}

?

Entonces quizá hayas eliminado las [direcciones de enlace](http://es.wikipedia.org/wiki/Direcci%C3%B3n_de_Enlace-Local) de la interfaz.

Las direcciones de enlace son utilizadas por muchos protocolos de IPv6 relevantes. En particular, son utilizadas por el *Protocolo de Descubrimiento de Vecinos*, lo que significa que si no las tienes, la máquina de traducción tendrá problemas para encontrar a sus vecinos IPv6.

Observa la salida de `ip addr`.

<div class="highlight"><pre><code class="bash">user@T:~$ /sbin/ip address
1: lo: &lt;LOOPBACK,UP,LOWER_UP&gt; mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: <strong>eth0</strong>: &lt;BROADCAST,MULTICAST,UP,LOWER_UP&gt; mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 08:00:27:83:d9:40 brd ff:ff:ff:ff:ff:ff
    inet6 2001:db8:aaaa::1/64 <strong>scope global</strong> 
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe83:d940/64 <strong>scope link</strong> 
       valid_lft forever preferred_lft forever
3: <strong>eth1</strong>: &lt;BROADCAST,MULTICAST,UP,LOWER_UP&gt; mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 08:00:27:c6:01:48 brd ff:ff:ff:ff:ff:ff
    inet6 2001:db8:bbbb::1/64 <strong>scope global</strong> tentative 
       valid_lft forever preferred_lft forever
</code></pre></div>

La interfaz _eth0_ está correctamente configurada; tiene tanto una dirección de "alcance global" (utilizada para un tráfico típico) y una dirección de "alcance de enlace" (utilizada para administración interna). La interfaz _eth1_ carece de una dirección de enlace, y como resultado tiende a inducir dolores de cabeza.

La manera más facil de restaurar las "direcciones de "alcance de enlace", que hemos encontrado, es reiniciar la interfaz:

{% highlight bash %}
ip link set eth1 down
ip link set eth1 up
{% endhighlight %}

Si, hablo en serio:

<div class="highlight"><pre><code class="bash">user@T:~$ /sbin/ip address
1: lo: &lt;LOOPBACK,UP,LOWER_UP&gt; mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: &lt;BROADCAST,MULTICAST,UP,LOWER_UP&gt; mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 08:00:27:83:d9:40 brd ff:ff:ff:ff:ff:ff
    inet6 2001:db8:aaaa::1/64 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe83:d940/64 scope link 
       valid_lft forever preferred_lft forever
3: eth1: &lt;BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 08:00:27:c6:01:48 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::a00:27ff:fec6:148/64 <strong>scope link</strong> 
       valid_lft forever preferred_lft forever
</code></pre></div>

(Toma en cuenta que necesitas agregar la dirección global de nuevo.)

Como referencia futura, ten en mente que la manera "correcta" de vaciar una interfaz es


{% highlight bash %}
ip addr flush dev eth1 scope global
{% endhighlight %}

IPv4 es menos problemático con direcciones de enlace.


## El rendimiento es terrible!

[Deshabilita offloads!](offloading.html)

Si estás ejecutando Jool en una máquina virtual huésped, algo importante que debes considerar es que quizá tengas que deshabilitar los offloads en el enlace ascendente de la [máquina virtual](http://en.wikipedia.org/wiki/Hypervisor).

## No puedo hacer ping a la dirección IPv4 del pool.

En realidad, esto es normal en Jool 3.2.x y versiones anteriores. La dirección destino del ping es traducible, de modo que Jool se está robando el paquete. Desafortunadamente, no tiene ningún registro relevante en la BIB (porque el ping no fue iniciado desde IPv6), así que la traducción falla (y el paquete es desechado).

Simplemente trata pingueando a la dirección del nodo.

Jool 3.3+ maneja mejor esto, de modo que el ping debería ser exitoso.

