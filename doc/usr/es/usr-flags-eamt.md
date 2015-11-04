---
language: es
layout: default
category: Documentation
title: --eamt
---

[Documentación](documentation.html) > [Aplicación de Espacio de Usuario](documentation.html#aplicacin-de-espacio-de-usuario) > `--eamt`

# \--eamt

## Índice

1. [Descripción](#descripcin)
2. [Sintaxis](#sintaxis)
3. [Options](#opciones)
   2. [Operaciones](#operaciones)
   4. [`--csv`](#csv)
   5. [`<prefix4>`, `<prefix6>`](#prefix4-prefix6)
4. [Ejemplos](#ejemplos)

## Descripción

Interactúa con la EAMT (_Tabla de mapeos explícitos de direcciones_). Ver [la introducción](intro-xlat.html#siit-con-eam) para una visión general rápida, el [resumen del draft](eamt.html) para más detalles, o el [draft]({{ site.draft-siit-eam }}) para todos los detalles.

## Sintaxis

	jool_siit --eamt [--display] [--csv]
	jool_siit --eamt --count
	jool_siit --eamt --add <prefix4> <prefix6>
	jool_siit --eamt --remove (<prefix4> | <prefix6> | <prefix4> <prefix6>)
	jool_siit --eamt --flush

## Opciones

### Operaciones

* `--display`: La tabla EAMT es impresa en salida estándar. Esta es la operación por defecto.
* `--count`: El número de registros en la tabla EAMT es impreso en salida estándar.
* `--add`: Combina `<prefix4>` y `<prefix6>` en un registro EAM, y lo carga a la tabla de Jool.
* `--remove`: Borra de la tabla el registro EAM descrito por `<prefix4>` y/o `<prefix6>`. 
* `--flush`: Remueve todos los registros de la tabla.

### `--csv`

Por defecto, la aplicación imprime las tablas en un formato relativamente amigable para la consola.

`--csv` se puede usar para imprimir en [formato CSV](http://es.wikipedia.org/wiki/CSV), que es amigable con software de hojas de cálculo.


### `<prefix4>`, `<prefix6>`

	<prefix4> := <IPv4 address>[/<prefix length>]
	<prefix6> := <IPv6 address>[/<prefix length>]

Estos son los prefijos con los cuales está conformado cada registro (ver la [explicación general de EAMT](eamt.html)).

Por defecto, `<prefix length>` es /32 en `<prefix4>` y /128 en `<prefix6>`.

Todo prefijo es único a lo largo de la tabla, por lo que solamente es necesario especificar uno de ellos cuando se desea remover. Sin embargo, es legal introducirlos ambos en el comando para garantizar que se está removiendo lo que se espera.



## Ejemplos

Agregar un puñado de mapeos:

{% highlight bash %}

# jool_siit --eamt --add 192.0.2.1      2001:db8:aaaa::
# jool_siit --eamt --add 192.0.2.2/32   2001:db8:bbbb::b/128
# jool_siit --eamt --add 192.0.2.16/28  2001:db8:cccc::/124
# jool_siit --eamt --add 192.0.2.128/26 2001:db8:dddd::/64
# jool_siit --eamt --add 192.0.2.192/31 64:ff9b::/127
{% endhighlight %}

Desplegar la nueva tabla:

{% highlight bash %}
$ jool_siit --eamt --display
64:ff9b::/127 - 192.0.2.192/31
2001:db8:dddd::/64 - 192.0.2.128/26
2001:db8:cccc::/124 - 192.0.2.16/28
2001:db8:bbbb::b/128 - 192.0.2.2/32
2001:db8:aaaa::/128 - 192.0.2.1/32
  (Fetched 5 entries.)
{% endhighlight %}

Escribir la tabla en un archivo csv:

{% highlight bash %}
$ jool_siit --eamt --display --csv > eamt.csv
{% endhighlight %}

[eamt.csv](../obj/eamt.csv)

Desplegar el número de registros en la tabla:

{% highlight bash %}
$ jool_siit --eamt --count
5
{% endhighlight %}

Remover el primer registro:

{% highlight bash %}
# jool_siit --eamt --remove 2001:db8:aaaa::
{% endhighlight %}

Vaciar la tabla:

{% highlight bash %}
# jool_siit --eamt --flush
{% endhighlight %}
