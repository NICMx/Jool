---
language: es
layout: default
category: Documentation
title: --pool4
---

[Documentación](documentation.html) > [Herramienta de configuración de Jool](documentation.html#aplicacion-de-espacio-de-usuario) > [Flags](usr-flags.html) > \--pool4

# \--pool4

## Índice

1. [Descripción](#descripcion)
2. [Sintaxis](#sintaxis)
3. [Argumentos](#argumentos)
4. [Ejemplos](#ejemplos)
5. [Notas](#notas)
6. [`--mark`](#mark)

## Descripción

Interactúa con el [pool de direcciones de transporte IPv4](pool4.html).

pool4 es el subconjunto de direcciones de transporte IPv4 del nodo que puede ser utilizado para traducir. 

Si pool4 está vacío, Jool tratará de enmascarar paquetes usando las direcciones (y puertos desocupados por defecto) de su propio nodo. Ver [notas](#notas).

## Sintaxis

	jool --pool4 [--display] [--csv]
	jool --pool4 --count
	jool --pool4 --add [--mark <mark>] [--tcp] [--udp] [--icmp] <IPv4 prefix> [<port range>] [--force]
	jool --pool4 --remove [--mark <mark>] [--tcp] [--udp] [--icmp] <IPv4 prefix> [<port range>] [--quick]
	jool --pool4 --flush [--quick]

## Argumentos

Operaciones:

* `--display`: Lista el contenido de pool4 en salida estándar. Esta es la operación por defecto.
* `--count`: Lista el número de tablas (grupos de muestras que comparten marca y protocolo), marcas (renglones) y direcciones de transporte contenidas en el pool.
* `--add`: Forma renglones a partir de los especificado por los parámetros y los registra en pool4.
* `--remove`: Elimina de pool4 las direcciones de transporte que satisfacen los parámetros.
* `--flush`: Vacía pool4.

Otros:

| **Name** | **Default** | **Description** |
| `--csv` | (ausente) | Si está presente, la tabla se imprimirá en [formato CSV](https://es.wikipedia.org/wiki/CSV). |
| `--mark` | 0 | Paquetes que contengan la marca _n_ solamente van a ser traducidos utilizando registros de pool4 que contengan la marca _n_. Ver [abajo](#mark). |
| `--tcp` | * | Si está presente, los puertos representan al protocolo TCP. |
| `--udp` | * | Si está presente, los puertos representan al protocolo UDP. |
| `--icmp` | * | Si está presente, los "puertos" representan identificadores de ICMP. |
| `<IPv4 prefix>` | - | Dirección o grupo de direcciones siendo agregados a pool4. La longitud por defecto es 32. |
| `<port range>` | 1-65535 para TCP/UDP, 0-65535 para ICMP | Subconjunto de de puertos (o identificadores ICMP) de la dirección que deben ser reservados para traducción. |
| `--force` | (ausente) | Si está presente, agregar los elementos al pool incluso si son demasiados.<br />(Si no se incluye, imprimirá una advertencia y cancelará la operación.) |
| `--quick` | (ausente) | Si está presente, no se borrarán las entradas BIB que correspondan al registro pool4 siendo removido.<br />`--quick` es más rápido, no `--quick` deja la base de datos más limpia (y por lo tanto más eficiente).<br />Entradas BIB sobrantes van a ser de todos modos removidas de la base de datos una vez expiren naturalmente.<br />[Aquí](usr-flags-quick.html) hay una explicación más elaborada. |

\* `--tcp`, `--udp` e `--icmp` no son mútuamente excluyentes. Si ninguna de las tres está presente, los registros se dan de alta a los tres protocolos.

## Ejemplos

Mostrar las direcciones actuales:

{% highlight bash %}
$ jool --pool4 --display 
  (empty)
{% endhighlight %}

Agregar varias entradas:

{% highlight bash %}
# jool --pool4 --add 192.0.2.1
$ jool --pool4 --display
0	ICMP	192.0.2.1	0-65535
0	UDP	192.0.2.1	1-65535
0	TCP	192.0.2.1	1-65535
  (Fetched 3 entries.)
# jool --pool4 --add          --tcp 192.0.2.2 7000-7999
# jool --pool4 --add --mark 1 --tcp 192.0.2.2 8000-8999
# jool --pool4 --add          --tcp 192.0.2.4/31
$ jool --pool4 --display
0	ICMP	192.0.2.1	0-65535
0	UDP	192.0.2.1	1-65535
0	TCP	192.0.2.1	1-65535
0	TCP	192.0.2.2	7000-7999
0	TCP	192.0.2.4	1-65535
0	TCP	192.0.2.5	1-65535
1	TCP	192.0.2.2	8000-8999
  (Fetched 7 entries.)
{% endhighlight %}

Borrar varias entradas:

{% highlight bash %}
# jool --pool4 --remove --mark 0 192.0.2.0/24 0-65535
$ jool --pool4 --display
1	TCP	192.0.2.2	8000-8999
  (Fetched 1 entries.)
{% endhighlight %}

Limpiar la tabla:

{% highlight bash %}
# jool --pool4 --flush
$ jool --pool4 --display
  (empty)
{% endhighlight %}

## Notas

TODO

## `--mark`
