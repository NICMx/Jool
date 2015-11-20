---
language: es
layout: default
category: Documentation
title: --bib
---

[Documentación](documentation.html) > [Aplicación de Espacio de Usuario](documentation.html#aplicacin-de-espacio-de-usuario) > `--bib`

# \--bib

## Índice

1. [Descripción](#descripcin)
2. [Sintaxis](#sintaxis)
3. [Argumentos](#argumentos)
   1. [Operaciones](#operaciones)
   2. [Opciones](#opciones)
4. [Ejemplos](#ejemplos)

## Descripción

Interactúa con el [Binding Information Base (BIB)](bib.html) de Jool.


## Sintaxis

	jool --bib [--tcp] [--udp] [--icmp] (
		[--display] [--numeric] [--csv]
		| --count
		| --add <dirección-de-transporte-IPv4> <dirección-de-transporte-IPv6>
		| --remove <dirección-de-transporte-IPv4> <dirección-de-transporte-IPv6>
	)

## Argumentos

### Operaciones

* `--display`: Lista las tablas BIB. Operación por omisión.
* `--count`: Lista el número de registros BIB en las tablas.
* `--add`: Combina `<dirección-de-transporte-IPv4>` e `<dirección-de-transporte-IPv6>` en un registro BIB estático, y lo añade a las tablas de Jool.  
La dirección de transporte IPv4 debe ser un miembro de [pool4](pool4.html) (de modo que es necesario registrarlo ahí primero).
* `--remove`: Borra el registro descrito por `<dirección-de-transporte-IPv4>` y/o `<dirección-de-transporte-IPv6>` de las tablas BIB.  
Toda dirección de transporte es única a lo largo de una tabla, de modo que solamente es mandatario especificar una de ellas al remover. Sin embargo, es legal introducirlas ambas en el comando para confirmar que se está removiendo lo que se espera.

### Opciones

| **Bandera** | **Descripción** |
| `--tcp` | Si está presente, el comando aplica sobre la tabla BIB de TCP. |
| `--udp` | Si está presente, el comando aplica sobre la tabla BIB de UDP. |
| `--icmp` | Si está presente, el comando aplica sobre la tabla BIB de ICMP. |
| `--numeric` | La aplicación intentará resolver el nombre del nodo IPv6 de cada registro BIB. _Si los nameservers no están respondiendo, la salida se retrasará_.<br />`--numeric` desactiva la resolución de nombres. |
| `--csv` | Imprimir la tabla en formato [CSV](https://es.wikipedia.org/wiki/CSV). La idea es redireccionar esto a un archivo .csv. |

\* `--tcp`, `--udp` e `--icmp` no son mutuamente excluyentes. Si ninguna de las tres está presente, el comando aplica a los tres protocolos.

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

[bib.csv](../obj/bib.csv)

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

