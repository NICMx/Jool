---
layout: documentation
title: Documentación - DNS64
---

[Documentación](esp-doc-index.html) > [Ejemplos de uso](esp-doc-index.html#ejemplos-de-uso) > DNS64

# Tutorial DNS64

## Índice

1. [Introducción](#introduccion)
2. [Red](#red)
3. [Configuración](#configuracion)
   1. [BIND](#bind)
   2. [Todo lo demás](#todo-lo-demas)
4. [Resultado](#resultado)

## Introducción

Este documento se enfoca en DNS64, la última llave para tener una instalación de NAT64 completamente coherente.

Cualquier implementación correcta de DNS64 se supone debería funcionar; BIND será utilizado para efecto de ilustrar. Espero que estes familiarizado con DNS y que tengas una idea por lo menos de como luce la configuración de BIND.

## Red

![Fig.1 - Setup](images/tut4-setup.svg)

Aunque Jool y el DNS64 son ilustrados como nodos separados, no hay nada que te prevenga de unirlos en una sola máquina (a menos de que Jool esté monopolizando todas las direcciones IPv4 de sus nodos, por supuesto).

## Configuración

### BIND

Primero, voy a dejar en claro lo que queremos lograr.

`example.com` es un dominio que esta disponible ambas la Internet IPv4 y la IPv6, y por lo tanto tiene ambos tipos de registros:

{% highlight bash %}
$ dig example.com A
(...)
;; ANSWER SECTION:
example.com.		66029	IN	A	93.184.216.119
(...)

$ dig example.com AAAA
(...)
;; ANSWER SECTION:
example.com.		86040	IN	AAAA	2606:2800:220:6d:26bf:1447:1097:aa7
(...)
{% endhighlight %}

`nat64-tutorial.mx` es un ejemplo de un dominio disponible solo desde IPv4:

{% highlight bash %}
$ dig nat64-tutorial.mx A
(...)
;; ANSWER SECTION:
nat64-tutorial.mx.	66029	IN	A	200.94.182.36
(...)

$ dig nat64-tutorial.mx AAAA
(...)
;; AUTHORITY SECTION:
nat64-tutorial.mx.	240	IN	SOA	potato.mx. hostmaster.jool.mx. 2013070801 3600 900 604800 1800
(...)
{% endhighlight %}

No hay necesidad de que un nodo IPv6 accese `example.com` mediante el NAT64. Por otra parte, `nat64-tutorial.mx` no puede ser accesado desde IPv6 si uno.

En otras palabras, queremos que el servicio de DNS64 devuelva `2606:2800:220:6d:26bf:1447:1097:aa7` cuando le sea solicitado el registro AAAA de `example.com` (que es lo que normalmente hace), y `64:ff9b::200.94.182.36` (ej. el prefijo NAT64 mas la direccion IPv4) cuando le sea solicitado el registro AAAA de `nat64-tutorial.mx` (el cual es el hack NAT64 completo).  


Primero, ten funcionando un servidor BIND. En Ubuntu, lo único que teines que hacer (assumiendo que todavia no tienes uno) es ejecutar

{% highlight bash %}
user@B:~# apt-get install bind9
{% endhighlight %}

La configuración mas básica es muy minimalista. 

The most basic configuration is very minimalistic. Para activar DNS64, la sección de opciones del archivo named.conf (en mi caso, `/etc/bind/named.conf.options`) es la única que debe ser actualizada:

{% highlight bash %}
options {
	(...)

	# Listening on IPv6 is off by default.
	listen-on-v6 { any; };

	# This is the key. Note that you can write multiple of these if you need
	# more IPv6 prefixes.
	# "64:ff9b::/96" has to be the same as Jool's `pool6`.
	dns64 64:ff9b::/96 {
		# Options per prefix (if you need them) here.
		# More info here: https://kb.isc.org/article/AA-01031
	};
};
{% endhighlight %}

Y recuerda recargar.

{% highlight bash %}
user@B:~# sudo service bind9 restart
{% endhighlight %}

Eso es todo!

### Todo lo demás

Las redes mas externas cambiaron, y eso deberia ser reflejado probablemente en las tablas de ruteo de todos:

{% highlight bash %}
user@J:~# /sbin/ip -6 route del 2001:db8:1::/64
user@J:~# /sbin/ip -6 route add default via 2001:db8:2::1 dev eth0
{% endhighlight %}

(Instrucciones similares deberían ser replicadas en los routers y los nodos)

Jool o J no necesita estar consciente del DNS64 por que los nombres de dominio son completamente transparentes a NAT64, asi que no necesitas hacer nadamas en J. 

En cuanto a los nodos hoja, cualquier nodo IPv6 que necesita acceder solo a contenido IPv4 _debe_ utilizar el DNS64 como su servidor de nombres por default (a menos de que quieras especificarlo manualmente en tus comandos dig, supongo).

## Resultado

Desde uno de esos nodos IPv6:

{% highlight bash %}
$ dig example.com AAAA
(...)
;; ANSWER SECTION:
example.com.		86040	IN	AAAA	2606:2800:220:6d:26bf:1447:1097:aa7
(...)

$ dig nat64-tutorial.mx AAAA
(...)
;; AUTHORITY SECTION:
nat64-tutorial.mx.	86040	IN	AAAA	64:ff9b::c85e:b624
(...)
{% endhighlight %}

Si monitoreas el trafico, deberias ver paqueter hacia `example.com` en R, y paquetes hacia `nat64-tutorial.mx` mediante S:

![Fig.2 - Arrows](images/tut4-arrows.svg)

Final Feliz!
