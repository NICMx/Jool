---
language: es
layout: default
category: Documentation
title: --pool6
---

[Documentation](documentation.html) > [Herramienta de configuración de Jool](documentation.html#aplicacion-de-espacio-de-usuario) > [Parámetros](usr-flags.html) > \--pool6

# \--pool6

## Índice

1. [Descripción](#descripcin)
2. [Sintaxis](#sintaxis)
3. [Opciones](#opciones)
   1. [Operaciones](#operaciones)
   2. [`--quick`](#quick)
4. [Ejemplos](#ejemplos)

## Descripción

Interactúa con el pool IPv6 de Jool. El "pool" contiene el prefijo del [RFC 6052](https://tools.ietf.org/html/rfc6052), que es el prefijo de traducción básico que se agrega y remueve de direcciones IPv4 en [SIIT tradicional](intro-xlat.html#siit-traditional) y [NAT64](intro-xlat.html#stateful-nat64).

A pesar de que tanto en Jool como en el RFC se le llama "pool", realmente no tiene sentido que tenga más de un prefijo porque no hay manera actualmente de mapearlo a interfaces o entradas de [pool4](pool4.html). Esto puede cambiar en el futuro. NAT64 Jool permite insertar más de un prefijo, pero solo por razones de compatibilidad hacia atrás (la traducción siempre utiliza solamente el primer prefijo). SIIT Jool no permite más de un prefijo.

Si el pool está vacío, Jool no va a poder traducir direcciones basado en el RFC 6052 (pero SIIT Jool aún puede traducir basado en la EAMT).

## Sintaxis

(`$(jool)` puede ser `jool_siit` o `jool`.)

	$(jool) --pool6 [--display]
	$(jool) --pool6 --count
	$(jool) --pool6 --add <IPv6 prefix>
	$(jool) --pool6 --remove <IPv6 prefix> [--quick]
	$(jool) --pool6 --flush [--quick]

## Opciones

### Operaciones

* `--display`: Lista los prefijos dados de alta y activos del pool. Esta es la operación por omisión.
* `--count`: Lista la cantidad de prefijos dados de alta y activos en el pool.
* `--add`: Agrega el prefijo `<prefix>` al pool.
* `--remove`: Borra de la tabla el prefijo `<prefix>`.
* `--flush`: Remueve todos los prefijos del pool.

### `--quick`

Ver [`--quick`](usr-flags-quick.html). Solo disponible en `jool`.

## Ejemplos

Desplegar los prefijos:

{% highlight bash %}
$ jool --pool6 --display
64:ff9b::/96
  (Fetched 1 prefixes.)
{% endhighlight %}

Mostrar el número de prefijos:

{% highlight bash %}
$ jool --pool6 --count
1
{% endhighlight %}

Remover el [_Well-Known Prefix_](https://tools.ietf.org/html/rfc6052#section-2.1):

{% highlight bash %}
$ jool --pool6 --remove 64:ff9b::/96
{% endhighlight %}

Añadir un prefijo:

{% highlight bash %}
$ jool --pool6 --add 2001:db8::/64
{% endhighlight %}

Destruir todos los prefijos:

{% highlight bash %}
$ jool --pool6 --flush --quick
{% endhighlight %}
