---
language: es
layout: default
category: FAQ
title: FAQ/Solución de problemas
---

[Documentación](documentation.html) > [Otros](documentation.html#miscellaneous) > FAQ/Solución de problemas

# FAQ/Solución de problemas

Esto resume problemas con los cuales algunos usuarios se han topado.


## Inserté a Jool pero no parece estar haciendo nada.

Insertar a Jool al kernel sin argumentos suficientes es legal. Jool asumirá que se intenta terminar de configurar utilizando la aplicación de espacio de usuario, y se mantendrá inactivo hasta que se haya hecho.

El parámetro [`--global`](usr-flags-global.html#description) despliega, junto con otros parámetros, el estado en el cual se encuentra Jool:

{% highlight bash %}
$ jool_siit --global
  Status: Disabled
{% endhighlight %}

{% highlight bash %}
$ jool --global
  Status: Disabled
{% endhighlight %}

Los requerimientos mínimos de configuración de SIIT Jool son:

- Un prefijo en [pool6](usr-flags-pool6.html) **o** por lo menos un registro en la [EAMT](usr-flags-eamt.html).
- No debe estar [manualmente deshabilitado](usr-flags-global.html#enable---disable).

Los requerimientos mínimos de configuración de NAT64 Jool son:

- Por lo menos un prefijo en [pool6](usr-flags-pool6.html).
- No debe estar [manualmente deshabilitado](usr-flags-global.html#enable---disable).

Si eso no parece ser el problema, los [logs](#logging.html) pueden tener algo que decir.


## Jool es intermitentemente incapaz de traducir tráfico.

Quizá se ejecutó algo como lo siguiente:

{% highlight bash %}
ip addr flush dev eth1
{% endhighlight %}

Esa instrucción elimina las [direcciones de enlace](http://es.wikipedia.org/wiki/Direcci%C3%B3n_de_Enlace-Local) de la interfaz.

Las direcciones de enlace son utilizadas por varios protocolos de IPv6 relevantes. En particular, son utilizadas por el *Protocolo de Descubrimiento de Vecinos*, lo que significa que su ausencia causa problemas para encontrar vecinos.

Las direcciones de enlace pueden encontrarse ejecutando `ip addr`.

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

La interfaz _eth0_ está correctamente configurada; tiene tanto una dirección de "alcance global" (utilizada para un tráfico típico) y una dirección de "alcance de enlace" (utilizada para administración interna). La interfaz _eth1_ carece de una dirección de enlace, y por lo tanto tiende a inducir dolores de cabeza.

Una manera sencilla de restaurar las direcciones de enlace es reiniciar la interfaz:

<div class="highlight"><pre><code class="bash">user@T:~$ ip link set eth1 down
user@T:~$ ip link set eth1 up
user@T:~$ ip address
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

(Nótese que es necesario agregar la dirección global de nuevo.)

Adicionalmente, es útil tener en mente que la manera "correcta" de vaciar una interfaz es

{% highlight bash %}
ip addr flush dev eth1 scope global
{% endhighlight %}

IPv4 es menos problemático con direcciones de enlace.


## El rendimiento es terrible!

[Hay que apagar offloads!](offloads.html)

Si Jool se está ejecutando en una máquina virtual huésped, puede ser necesario deshabilitar offloads también en la máquina host.

