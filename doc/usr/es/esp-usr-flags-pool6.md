---
layout: documentation
title: Documentación - Parámetros > Pool IPv6
---

[Documentation](esp-doc-index.html) > [Aplicación de espacio de usuario](esp-doc-index.html#aplicacin-de-espacio-de-usuario) > [Parámetros](esp-usr-flags.html) > \--pool6

# \--pool6

## Índice

1. [Descripción](#descripcin)
2. [Sintaxis](#sintaxis)
3. [Opciones](#opciones)
   1. [Operaciones](#operaciones)
   2. [`--quick`](#quick)
4. [Ejemplos](#ejemplos)

## Descripción

Interactua con el pool IPv6 de Jool. El pool dicta que paquetes viniendo del lado IPv6 son procesados; si la dirección de destino de un paquete entrante tiene uno de los prefijos IPv6, el paquete es traducido. De otra manera es entregado al kernel para ser redireccionado de alguna manera o ser entregado a las capas superiores.



## Sintaxis

(`$(jool)` puede ser `jool_siit` o `jool`.)

	$(jool) --pool6 [--display]
	$(jool) --pool6 --count
	$(jool) --pool6 --add <IPv6 prefix>
	$(jool) --pool6 --remove <IPv6 prefix> [--quick]
	$(jool) --pool6 --flush [--quick]

## Opciones

### Operaciones

* `--display`: Muestra los prefijos dados de alta y activos del Pool.<br /> Operación por Omisión
* `--count`: Muestra la cantidad de prefijos dados de alta y activos del Pool.
* `--add`: Agrega el `<prefix>`al pool.
* `--remove`: Borra de las tablas el prefijo `<prefix>`.
* `--flush`: Remueve todos los prefijos del pool.

### `--quick`

Ver [`--quick`](esp-usr-flags-quick.html). Solo disponible en NAT64 Stateful.

## Ejemplos

Despliega los prefijos activos:

{% highlight bash %}
$ jool --pool6 --display
64:ff9b::/96
  (Fetched 1 prefixes.)
{% endhighlight %}

Despliega el número de prefijos activos:

{% highlight bash %}
$ jool --pool6 --count
1
{% endhighlight %}

Remueve el prefijo por omisión (64:ff9b::/96):

{% highlight bash %}
$ jool --pool6 --remove 64:ff9b::/96
{% endhighlight %}

Añade un simple prefijo (2001:db8::/64):

{% highlight bash %}
$ jool --pool6 --add 2001:db8::/64
{% endhighlight %}

Destruye todos los prefijos. No te molestes limpiando la basura:

{% highlight bash %}
$ jool --pool6 --flush --quick
{% endhighlight %}
