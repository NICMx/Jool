---
layout: documentation
title: Documentación - Parámetros > EAMT
---

[Documentation](esp-doc-index.html) > [Aplicación de espacio de usuario](esp-doc-index.html#aplicacin-de-espacio-de-usuario) > [Parámetros](esp-usr-flags.html) > \--eamt

# \--eamt

## Índice

1. [Descripción](#description)
2. [Sintaxis](#sintaxis)
3. [Options](#options)
   2. [Operaciones](#operaciones)
   4. [`--csv`](#csv)
   5. [`<prefix4>`, `<prefix6>`](#prefix4-prefix6)
4. [Ejemplos](#ejemplos)

## Descripción

Interactua con la Tabla de mapeo de direcciones explícitas de Jool (EAMT) por sus siglas en inglés. Ve [la introducción](esp-intro-nat64.html#siit-with-eam) para una que tengas visión general rápida, nuestro [resumen de drafts](esp-misc-eamt.html) para mas detalles, o el [draft EAM](https://tools.ietf.org/html/draft-anderson-v6ops-siit-eam-02) para la historia completa.

## Sintaxis

	jool_siit --eamt [--display] [--csv]
	jool_siit --eamt --count
	jool_siit --eamt --add <prefix4> <prefix6>
	jool_siit --eamt --remove (<prefix4> | <prefix6> | <prefix4> <prefix6>)
	jool_siit --eamt --flush

## Opciones

### Operaciones

* `--display`: La tabla EAMT es impresa en la salida estandar. Esta es la operación por default.
* `--count`: El número de registros en la tabla EAMT es impreso a la salida estandar.
* `--add`: Combina `<prefix4>` y `<prefix6>` en un registro EAM, y lo carga a la tabla de Jool.
* `--remove`: Borra de la tabla el registro EAM descrito por `<prefix4>` y/o `<prefix6>`. 
* `--flush`: Remueve todos los registros de la tabla.

### `--csv`

Por default, la aplicación va a imprimir las tablas en un formato relativamente amigable para la consola.

Utiliza `--csv` para imprimir en [formato CSV](http://es.wikipedia.org/wiki/CSV) el cual es amigable con una hoja de cálculo.


### `<prefix4>`, `<prefix6>`

	<prefix4> := <IPv4 address>[/<prefix length>]
	<prefix6> := <IPv6 address>[/<prefix length>]

Estos son los prefijos de los cuales esta hecho cada registro, Ve la [explicación general EAMT](esp-misc-eamt.html)

`<prefix length>` es por default /32 en `<prefix4>` y /128 en `<prefix6>`. Jool pone en cero cualquier sufijo de cualquiera de las direcciones si existe.  

Todo prefijo es único a lo largo de la tabla. Por lo tanto, si estas removiendo un registro EAMT, solo necesitas proveer uno de ellos. Aun asi puedes ingresar ambos para asegurarte de que estas eliminando exactamente lo que quieres.



## Ejemplos

Agrega un puñado de mapeos:

{% highlight bash %}

# jool_siit --eamt --add 192.0.2.1      2001:db8:aaaa::
# jool_siit --eamt --add 192.0.2.2/32   2001:db8:bbbb::b/128
# jool_siit --eamt --add 192.0.2.16/28  2001:db8:cccc::/124
# jool_siit --eamt --add 192.0.2.128/26 2001:db8:dddd::/64
# jool_siit --eamt --add 192.0.2.192/31 64:ff9b::/127
{% endhighlight %}

Despliega la nueva tabla:

{% highlight bash %}
$ jool_siit --eamt --display
64:ff9b::/127 - 192.0.2.192/31
2001:db8:dddd::/64 - 192.0.2.128/26
2001:db8:cccc::/124 - 192.0.2.16/28
2001:db8:bbbb::b/128 - 192.0.2.2/32
2001:db8:aaaa::/128 - 192.0.2.1/32
  (Fetched 5 entries.)
{% endhighlight %}

Ingresa la base de datos en un archivo csv:

{% highlight bash %}
$ jool_siit --eamt --display --csv > eamt.csv
{% endhighlight %}

[eamt.csv](obj/eamt.csv)

Despliega el numero de registros en la tabla:

{% highlight bash %}
$ jool_siit --eamt --count
5
{% endhighlight %}

Remueve el primer registro:

{% highlight bash %}
# jool_siit --eamt --remove 2001:db8:aaaa::
{% endhighlight %}

Vacia la tabla:

{% highlight bash %}
# jool_siit --eamt --flush
{% endhighlight %}
