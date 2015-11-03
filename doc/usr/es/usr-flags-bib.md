---
language: es
layout: default
category: Documentation
title: --bib
---

[Documentación](documentation.html) > [Herramienta de configuración de Jool](documentation.html#aplicacion-de-espacio-de-usuario) > [Parámetros](usr-flags.html) > \--bib

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

Interactúa con el [Binding Information Base (BIB)](bib.html) de Jool.


## Sintaxis

	jool --bib <protocols> [--display] [--numeric] [--csv]
	jool --bib <protocols> --count
	jool --bib <protocols> --add <bib4> <bib6>
	jool --bib <protocols> --remove (<bib4> | <bib6> | <bib4> <bib6>)

## Opciones

### Operaciones

* `--display`: Lista las tablas BIB. Operación por omisión.
* `--count`: Lista el número de registros BIB en las tablas.
* `--add`: Combina `<bib6>` y `<bib4>` en un registro BIB estático, y lo añade a las tablas de Jool.
* `--remove`: Borra el registro descrito por `<bib6>` and/or `<bib4>` de las tablas BIB.

### `<protocols>`

	<protocols> := [--tcp] [--udp] [--icmp]

El comando aplica sobre la(s) tabla(s) específica(s). Si no se indica, entonces afecta a los tres protocolos.

### `--numeric`

La aplicación intentará resolver el nombre del nodo IPv6 de cada registro BIB. _Si los nameservers no están respondiendo, la salida se retrasará_.

`--numeric` desactiva la resolución de nombres.

### `--csv`

Por defecto, la aplicación imprime las tablas en un formato relativamente amigable para la consola.

`--csv` se puede usar para imprimir en [formato CSV](http://es.wikipedia.org/wiki/CSV), que es amigable con software de hojas de cálculo.


### `<bib4>`, `<bib6>`

	<bib4> := <dirección IPv4>#(<puerto> | <identificador ICMP>)
	<bib6> := <dirección IPv6>#(<puerto> | <identificador ICMP>)

Un registro BIB está compuesto de una dirección de transporte IPv6 (los identificadores de conexión de los nodos IPv6) y una dirección de transporte IPv4 (los identificadores de conexión que Jool está utilizando para enmascarar los de IPv6).

Estos parámetros definen la respectiva dirección de transporte al insertar o remover entradas. El componente `<bib4>` debe ser un miembro de [pool4](usr-flags-pool4.html) (de modo que es necesario registrarlo ahí antes de colocarlo en BIB).

Toda dirección de transporte única a lo largo de la base de datos, por lo que solamente es mandatario especificar de ellas al remover. Sin embargo, es legal introducirlos ambos en el comando para garantizar que se está removiendo lo que se espera.

## Ejemplos

Premisas:

* 4.4.4.4 pertenece a pool4.
* El nombre de 6::6 es "potato.mx".
* 6::6 se encuentra interactuando con un nodo de IPv4, de modo que la base de datos no está vacía.

Desplegar la base de datos:

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

Habilitar la recepción en un par de servicios TCP:

{% highlight bash %}
# jool --bib --add --tcp 6::6#6 4.4.4.4#4
# jool --bib --add --tcp 6::6#66 4.4.4.4#44
{% endhighlight %}

Listar la tabla TCP:

{% highlight bash %}
$ jool --bib --display --tcp
TCP:
[Static] 4.4.4.4#4 - potato.mx#6
[Static] 4.4.4.4#44 - potato.mx#66
[Dynamic] 4.4.4.4#1234 - potato.mx#1234
  (Fetched 3 entries.)
{% endhighlight %}

Listar la tabla TCP, no interactuar con el DNS:

{% highlight bash %}
$ jool --bib --display --tcp --numeric
TCP:
[Static] 4.4.4.4#4 - 6::6#6
[Static] 4.4.4.4#44 - 6::6#66
[Dynamic] 4.4.4.4#1234 - 6::6#1234
  (Fetched 3 entries.)
{% endhighlight %}

Publicar un servicio UDP:

{% highlight bash %}
# jool --bib --add --udp 6::6#6666 4.4.4.4#4444
{% endhighlight %}

Guardar la base de datos en un archivo CSV:

{% highlight bash %}
$ jool --bib --display --numeric --csv > bib.csv
{% endhighlight %}

[bib.csv](obj/bib.csv)

Mostrar cuántos registros hay en las tablas TCP e ICMP:

{% highlight bash %}
$ jool --bib --count --tcp --icmp
TCP: 3
ICMP: 0
{% endhighlight %}

Remover la máscara de un servicio UDP:

{% highlight bash %}
# jool --bib --remove --udp 6::6#6666
{% endhighlight %}

