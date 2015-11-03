---
language: es
layout: default
category: Documentation
title: DNS64
---

[Documentación](documentation.html) > [Ejemplos de uso](documentation.html#ejemplos-de-uso) > DNS64

# Tutorial DNS64

## Índice

1. [Introducción](#introduccin)
2. [Red](#red)
3. [Configuración](#configuracin)
   1. [BIND](#bind)
   2. [Todo lo demás](#todo-lo-dems)
4. [Resultado](#resultado)

## Introducción

Este documento se enfoca en DNS64, el último componente para tener una instalación de NAT64 completamente coherente.

Cualquier implementación correcta de DNS64 debe funcionar; BIND será utilizado para ilustrar la idea. Este tutorial asume familiarización con DNS y archivos de configuración de BIND.

## Red

![Fig.1 - Setup](../images/tut4-setup.svg)

Aunque Jool y el DNS64 son ilustrados como nodos separados, nada (además de [colisión de puertos](pool4.html#notas)) previene unirlos en una sola máquina.

## Configuración

### BIND

Primero voy a explicar lo que deseamos lograr.

`example.com` es un dominio que está disponible tanto en IPv4 como en IPv6, y por lo tanto tiene ambos tipos de registros:

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

No hay necesidad de que un nodo de IPv6 acceda a `example.com` mediante un NAT64. En contraste, necesita un traductor para acceder a `nat64-tutorial.mx`.

En otras palabras, queremos que el servicio de DNS devuelva `2606:2800:220:6d:26bf:1447:1097:aa7` cuando le sea solicitado el registro AAAA de `example.com` (que es lo que normalmente hace), y `64:ff9b::200.94.182.36` (ie. el prefijo de traducción más la dirección IPv4) cuando le sea solicitado el registro AAAA de `nat64-tutorial.mx`.

Lo primero es tener un servidor BIND instalado. En Ubuntu, lo único que tengo que hacer para llegar a esto es

{% highlight bash %}
user@B:~# apt-get install bind9
{% endhighlight %}

La configuración mas básica es muy minimalista. Para activar DNS64, la sección de opciones del archivo `named.conf` (en mi caso, `/etc/bind/named.conf.options`) es la única que debe ser actualizada:

	options {
		(...)

		# Escuchar por IPv6 está desactivado por defecto.
		listen-on-v6 { any; };

		# Esto es la llave. Nótese que es posible tener varios de estos si se necesitan
		# múltiples prefijos de traducción.
		# "64:ff9b::/96" tiene que ser lo mismo que Jool conoce como "pool6".
		dns64 64:ff9b::/96 {
			# Opciones por prefijo (si se necesitan) aquí.
			# Más información aquí: https://kb.isc.org/article/AA-01031
		};
	};

Y recuerda recargar.

{% highlight bash %}
user@B:~# sudo service bind9 restart
{% endhighlight %}

Eso es toda la configuración que requiere el nodo que va a servir DNS.

### Todo lo demás

Las redes mas externas cambiaron, y eso probablemente debe ser reflejado  en las tablas de ruteo de todos:

{% highlight bash %}
user@J:~# /sbin/ip -6 route del 2001:db8:1::/64
user@J:~# /sbin/ip -6 route add default via 2001:db8:2::1 dev eth0
{% endhighlight %}

(Instrucciones similares deberían ser replicadas en los routers y los nodos.)

_J_ no necesita configuración adicional porque DNS64 es completamente transparente para NAT64.

En cuanto a los nodos hoja, cualquier nodo IPv6 que necesita acceder a contenido IPv4 _debe_ utilizar el DNS64 como su servidor de nombres por defecto (a menos de que quieras especificarlo manualmente en tus comandos dig, supongo).

## Resultado

Desde uno de los nodos IPv6:

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

Si se monitorea el tráfico se debería observar que paquetes hacia `example.com` se van a través de _R_, y paquetes hacia `nat64-tutorial.mx` mediante _J_/_S_:

![Fig.2 - Arrows](../images/tut4-arrows.svg)

Final Feliz!
