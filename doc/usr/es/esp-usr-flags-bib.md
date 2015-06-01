---
layout: documentation
title: Documentación - Parámetros > BIB
---

[Documentación](esp-doc-index.html) > [Herramienta de configuración de Jool](esp-doc-index.html#aplicacion-de-espacio-de-usuario) > [Parámetros](esp-usr-flags.html) > \--bib

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

* `--display`: Lista las tablas BIB. Operación por omisión.
* `--count`: Lista el número de registros BIB.
* `--add`: Combina `<bib6>` y `<bib4>` en un registro BIB, y lo añade a las tablas de Jool.
* `--remove`: Borra el registro descrito por `<bib6>` and/or `<bib4>` de las tablas BIB.

### `<protocols>`

	<protocols> := [--tcp] [--udp] [--icmp]

El comando aplica sobre la(s) tabla(s) específica(s). Si no se indica, entonces afecta a los tres protocolos.

### `--numeric`

La aplicación intentará resolver el nombre del nodo IPv6 de cada registro BIB. _Si tus nameservers no estan respondiendo, esto realentizará la salida_.

Utiliza `--numeric` para desactivar este comportamiento.

### `--csv`

La aplicación muestra la información en un formato amigable para la consola.

Utiliza `--csv` para imprimir en [formato CSV](http://es.wikipedia.org/wiki/CSV) para abrirse como hoja de cálculo.

### `<bib4>`, `<bib6>`

	<bib4> := <dirección IPv4>#(<puerto> | <identificador ICMP>)
	<bib6> := <dirección IPv6>#(<puerto> | <identificador ICMP>)

Un registro BIB está compuesto de una dirección de transporte IPv6 (los identificadores de conexión de los nodos IPv6) y una dirección de transporte IPv4 (los identificadores de conexión que Jool está utilizando para enmascarar los de IPv6).

Si estas agregando o removiendo un BIB, puedes proveer ambas direcciones mediante estos parámetros.

Toma en cuenta que el componente `<bib4>` debe ser un miembro del [pool IPv4](esp-usr-flags-pool4.html) de Jool, así que asegurate de que lo has registrado ahí primero.

Dentro de una tabla BIB, toda dirección de transporte IPv4 es única. Dentro de una tabla BIB, toda dirección IPv6 también es única. Por lo tanto, si estas removiendo un registro BIB, sólo necesitas proveer uno de ellos. Aun puedes ingresar ambos para asegurarte de que estas eliminando exactamente lo que deseas.


## Ejemplos

Premisas:

* 4.4.4.4 pertenece al pool IPv4.
* El nombre de 6::6 es "potato.mx".
* 6::6 ya le habló a un nodo IPv4 recientemente, así que la base de datos no está vacía.

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

Habilita la recepción en un par de servicios TCP:

{% highlight bash %}
# jool --bib --add --tcp 6::6#6 4.4.4.4#4
# jool --bib --add --tcp 6::6#66 4.4.4.4#44
{% endhighlight %}

Lista la tabla TCP:

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

Guarda la base de datos en un archivo CSV:

{% highlight bash %}
$ jool --bib --display --numeric --csv > bib.csv
{% endhighlight %}

[bib.csv](obj/bib.csv)

Muestra cuantos registros hay en las tablas TCP e ICMP:

{% highlight bash %}
$ jool --bib --count --tcp --icmp
TCP: 3
ICMP: 0
{% endhighlight %}

Cancela el registro del servicio UDP:

{% highlight bash %}
# jool --bib --remove --udp 6::6#6666
{% endhighlight %}