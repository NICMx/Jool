---
language: es
layout: default
category: FAQ
title: FAQ/Solución de problemas
---

[Documentación](documentation.html) > [Otros](documentation.html#miscellaneous) > FAQ/Solución de problemas

# FAQ/Solución de problemas

Esto resume problemas en los cuales hemos visto que los usuarios se meten.


## Instalé el módulo de Jool pero no parece estar haciendo nada.

Instalar el módulo del Jool sin argumentos suficientes es legal. Asumirá que intentas terminar de configurar utilizando la Aplicación de espacio de usuario, y se mantendra inactivo hasta que lo hayas hecho.

Utiliza el parámetro [`--global`](usr-flags-global.html#description) para saber el estado en el que se encuentra Jool:

{% highlight bash %}
$ jool_siit --global
  Status: Disabled
{% endhighlight %}

{% highlight bash %}
$ jool --global
  Status: Disabled
{% endhighlight %}

Los requerimientos minimos de configuracion del SIIT de Jool son:

- Un prefijo en el [pool IPv6](usr-flags-pool6.html) **o** por lo menos un registro en la [tabla EAM](usr-flags-eamt.html).
- No debes de haberlo [deshabilitado manualmente](usr-flags-global.html#enable---disable).

Los requerimientos minimos de configuración de Stateful Jool son:

- Por lo menos un prefijo en el [pool IPv6](usr-flags-pool6.html).
- Por lo menosd un(a) prefijo/dirección en el [pool IPv4](usr-flags-pool4.html).
- No debes de haberlo [deshabilitado manualmente](usr-flags-global.html#enable---disable).


Si ese no es el problema, intenta habilitar la depuración mientras compilas.

	user@node:~/Jool-<version>/mod$ make debug

Reinstalalo. Jool sera mas descriptivo en `dmesg`:

	$ dmesg | tail -5
	[ 3465.639622] ===============================================
	[ 3465.639655] Catching IPv4 packet: 192.0.2.16->198.51.100.8
	[ 3465.639724] Translating the Packet.
	[ 3465.639756] Address 192.0.2.16 lacks an EAMT entry and there's no pool6 prefix.
	[ 3465.639806] Returning the packet to the kernel.

Si no esta imprimiendo nada a pesar de que estas habilitando la depuración, quizá es por que tu nivel de lo es muy alto. Ve [esto](http://elinux.org/Debugging_by_printing#Log_Levels).

Los mensajes de depuración se vuelven rápidamente gigabytes de log, asi que recuerda revertor esto antes de ponerlo en producción.


## Que hacer con este mensaje de error? Está horriblemente ambigüo.

Así es, los mensajes de respuesta del modulo del kernel hacia el espacio de usuario son muy primitivos. Podriamos mejorar realmente la comunicación con la Aplicación de espacio de usuario, pero no tenemos control sobre la comunicación de `modprobe`.

De cualquier forma, tendras mejor suerte leyendo los logs de Jool. Como con cualquier otro componente del kernel, los mensajes de Jool estan mezclados junto con otros y se pueden ver ejecutando `dmesg` En general, la mayor parte de los kernels son muy silenciosos una vez que han terminado la fase de arranque, asi que el mensaje mas reciente de Jool deberia encontrarse hasta el final.


{% highlight bash %}
$ sudo modprobe jool_siit pool6=2001:db8::/96 pool4=192.0a.2.0/24
ERROR: could not insert module jool_siit.ko: Invalid parameters
$ dmesg | tail -1
[28495.042365] SIIT Jool ERROR (parse_prefix4): IPv4 address or prefix is malformed:
192.0a.2.0/24.
{% endhighlight %}

{% highlight bash %}
$ sudo jool --bib --add --tcp 2001:db8::1#2000 192.0.2.5#2000
TCP:
Invalid input data or parameter (System error -7)
$ dmesg | tail -1
[29982.832343] NAT64 Jool ERROR (add_static_route): The IPv4 address and port could not be
reserved from the pool. Maybe the IPv4 address you provided does not belong to the pool.
Or maybe they're being used by some other BIB entry?
{% endhighlight %}

## Jool es intermitentemente incapaz de traducir tráfico.

Ejecutaste algo como:

{% highlight bash %}
ip addr flush dev eth1
{% endhighlight %}

?

Entonces quizá hayas eliminado las [direcciones de enlace](http://es.wikipedia.org/wiki/Direcci%C3%B3n_de_Enlace-Local) de la interfáz.

Las direcciónes de enlace son utilizadas por muchos portocolos IPv6 relevantes. En particular, son utilizadas por el *Protocolo de Descubrimiento de Vecinos*, lo que significa que si no las tienes, la máquina de traducción tendrá problemas para encontrar a sus vecinos IPv6.

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

La primera interfaz está correctamente configurada; tiene ambas una dirección de "alcance global" (utilizada para un tráfico típico) y una direccion de "alcance de enlace"(utilizada para administración interna). La interfáz _eth1_ carece de una dirección de enlace, y como resultado tiende a inducir dolores de cabeza.  

La manera más facil de restaurar las "direcciones de "alcance de enlace", que hemos encontrado, es reiniciar la interfaz:

{% highlight bash %}
ip link set eth1 down
ip link set eth1 up
{% endhighlight %}

Si, hablo encerio:

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

(Toma en cuenta que, necesitas agregar la dirección global de nuevo)

Tambien, como referencia futura, ten en mente que la manera "correcta" de vaciar una interfaz es


{% highlight bash %}
ip addr flush dev eth1 scope global
{% endhighlight %}

IPv4 no necesita direcciones de enlace.


## El rendimiento es terrible!

[deshabilita los offloads!](offloading.html)

Si estas ejecutando Jool en una máquina virtual huesped, algo importante que debes mantener en mente es que quizá prefieras o tambien tengas que deshabilitar los offloads en el enlace ascendente de la [máquina virtual](http://en.wikipedia.org/wiki/Hypervisor)

## No puedo hacer ping a la dirección IPv4 del pool.

De hecho, esto es normal en Jool 3.2.x y versiones anteriores. La dirección de destino del paquete ping es traducible, asi que Jool se esta robando el paquete. Desafortunadamente, no tiene ningun registro relevante en el BIB (por que el ping no fue iniciado desde IPv6), asi que la traducción falla( y el paquete es desechado).

Dejando de lado este aspecto extraño, no causa ninguna otra catastrofe; solo haz ping a la dirección del nodo.

Jool 3.3+ maneja mejor esto asi que el ping deberia de ser exitoso.
