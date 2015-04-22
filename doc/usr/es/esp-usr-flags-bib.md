---
layout: documentation
title: Documentación - Parámetros > BIB
---

[Documentación](esp-doc-index.html) > [Aplicación de espacio de usuario](esp-doc-index.html#aplicacin-de-espacio-de-usuario) > [Parámetros](esp-usr-flags.html) > \--bib

# \--bib

## Índice

1. [Descripción](#descripcion)
2. [Sintaxis](#sintaxis)
3. [Opciones](#opciones)
   1. [Operaciones](#operaciones)
   2. [`<protocols>`](#protocolos)
   3. [`--numeric`](#numeric)
   4. [`--csv`](#csv)
   5. [`<bib4>`, `<bib6>`](#bib4-bib6)
4. [Ejemplos](#ejemplos)

## Descripción

Interactua con el [Binding Information Base (BIB)](misc-bib.html) de Jool. Si no sabes que es, por favor sigue el enlace antes de continuar.


## Sintaxis

	jool --bib <protocols> [--display] [--numeric] [--csv]
	jool --bib <protocols> --count
	jool --bib <protocols> --add <bib4> <bib6>
	jool --bib <protocols> --remove (<bib4> | <bib6> | <bib4> <bib6>)

## Opciones

### Operaciones

* `--display`: Las tablas BIB son impresas en la salida estandar. Esta es la operación por default.
* `--count`: El numero de registros BIB es impreso en la salida estandar.
* `--add`: Combina `<bib6>` y `<bib4>` en un registro BIB, y lo carga a las tablas de Jool.
* `--remove`: Borra el registro descrito por `<bib6>` and/or `<bib4>` de las tablas BIB.

### `<protocols>`

	<protocols> := [--tcp] [--udp] [--icmp]

El comando sólo va a operar en las tablas mencionadas aquí. Si quieres omitir esto completamente, Jool retrocederá a operar en todas sus 3 tablas.

### `--numeric`

Por default, la aplicación nunca intentara resolver el nombre del nodo IPv6 de cada registro BIB. _Si tus nameservers no estan respondiendo, esto realentizará la salida_.

Utiliza `--numeric` para desactivar este comportamiento.

### `--csv`

Por default, la aplicación va a imprimir las tablas en un formato relativamente amigable para la consola.

By default, the application will print the tables in a relatively console-friendly format.

Utiliza `--csv` para imprimir en [formato CSV](http://es.wikipedia.org/wiki/CSV) el cual es amigable con una hoja de cálculo.

### `<bib4>`, `<bib6>`

	<bib4> := <dirección IPv4>#(<puerto> | <identificador ICMP>)
	<bib6> := <dirección IPv6>#(<puerto> | <identificador ICMP>)

Un registro BIB está compuesto de una dirección de transporte IPv6 (los identificadores de conexión de los nodos IPv6) y una dirección de transporte IPv4 (los identificadores de conexión que Jool está utilizando para enmascarar los de IPv6).

Si estas agregando o removiendo un BIB, provees ambas direcciones mediante estos parámetros.

Toma en cuenta que el componente `<bib4>` debe ser un miembro del [pool IPv4](esp-usr-flags-pool4.html) de Jool, así que asegurate de que lo has registrado ahí primero.

Dentro de una tabla BIB, toda dirección de transporte IPv4 es única. Dentro de una tabla BIB, toda dirección IPv6 también es única. Por lo tanto, si estas removiendo un registro BIB, sólo necesitas proveer uno de ellos. Aun puedes ingresar ambos para asegurarte de que estas eliminando exactamente lo que deseas.


## Ejemplos

Suposiciones:

* 4.4.4.4 pertenece al pool IPv4.
* El nombre de 6::6 es "potato.mx".
* 6::6 ya le habló a un nodo IPv4 recientemente, así que la base de datos no empezará vacía.

Despliega la base de datos entera:

{% highlight bash %}
$ jool --bib --display
TCP:
[Dynamic] 4.4.4.4#1234 - potato.mx#1234
  (Fetched 1 entries.)
UDP:
  (empty)
ICMP:
  (empty)
{% endhighlight %}

Publica un par de servicios TCP:

{% highlight bash %}
# jool --bib --add --tcp 6::6#6 4.4.4.4#4
# jool --bib --add --tcp 6::6#66 4.4.4.4#44
{% endhighlight %}

Despliega la tabla TCP:

{% highlight bash %}
$ jool --bib --display --tcp
TCP:
[Static] 4.4.4.4#4 - potato.mx#6
[Static] 4.4.4.4#44 - potato.mx#66
[Dynamic] 4.4.4.4#1234 - potato.mx#1234
  (Fetched 3 entries.)
{% endhighlight %}

Igual, pero no llama al DNS:

{% highlight bash %}
$ jool --bib --display --tcp --numeric
TCP:
[Static] 4.4.4.4#4 - 6::6#6
[Static] 4.4.4.4#44 - 6::6#66
[Dynamic] 4.4.4.4#1234 - 6::6#1234
  (Fetched 3 entries.)
{% endhighlight %}

Publica un servicio UDP:

{% highlight bash %}
# jool --bib --add --udp 6::6#6666 4.4.4.4#4444
{% endhighlight %}

Vacía la base de datos en un archivo CSV:

{% highlight bash %}
$ jool --bib --display --numeric --csv > bib.csv
{% endhighlight %}

[bib.csv](obj/bib.csv)

Despliega el numero de registros en las tablas TCP e ICMP:

{% highlight bash %}
$ jool --bib --count --tcp --icmp
TCP: 3
ICMP: 0
{% endhighlight %}

Remueve el registro UDP:

{% highlight bash %}
# jool --bib --remove --udp 6::6#6666
{% endhighlight %}