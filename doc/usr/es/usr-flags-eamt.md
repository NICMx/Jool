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
3. [Argumentos](#argumentos)
   1. [Operaciones](#operaciones)
   2. [Opciones](#opciones)
4. [Entradas EAM superpuestas](#entradas-eam-superpuestas)
4. [Ejemplos](#ejemplos)

## Descripción

Interactúa con la EAMT (_Tabla de mapeos explícitos de direcciones_). Ver [la introducción](intro-xlat.html#siit-con-eam) para una visión general rápida, el [resumen del draft](eamt.html) para más detalles, o el [draft]({{ site.draft-siit-eam }}) para todos los detalles.

## Sintaxis

	jool_siit --eamt (
		[--display] [--csv]
		| --count
		| --add <prefijo-IPv4> <prefijo-IPv6> [--force]
		| --remove <prefijo-IPv4> <prefijo-IPv6>
		| --flush
	)

## Argumentos

### Operaciones

* `--display`: La tabla EAMT es impresa en salida estándar. Esta es la operación por defecto.
* `--count`: El número de registros en la tabla EAMT es impreso en salida estándar.
* `--add`: Combina `<prefijo-IPv4>` y `<prefijo-IPv6>` en un registro EAM, y lo carga a la tabla de Jool.
* `--remove`: Borra de la tabla el registro EAM descrito por `<prefijo-IPv4>` y/o `<prefijo-IPv6>`.  
Todo prefijo es único a lo largo de la tabla, por lo que solamente es necesario especificar uno de ellos cuando se desea remover. Sin embargo, es legal introducirlos ambos en el comando para garantizar que se está removiendo lo que se espera.
* `--flush`: Remueve todos los registros de la tabla.

### Opciones

| **Bandera** | **Descripción** |
| `--csv` | Imprimir la tabla en formato [CSV](https://es.wikipedia.org/wiki/CSV). La idea es redireccionar esto a un archivo .csv. |
| `--force` | Dar de alta la entrada aún si ocurre superposición (ver la siguiente sección). |

## Entradas EAM superpuestas

Normalmente las entradas EAM no pueden colisionar entre sí. Es posible usar `--force` durante un `--add` para anular esta propiedad. Cuando existen entradas EAM que se superponen, Jool elige basado en prefijo común más largo.

Por ejemplo:

| Prefijo IPv4    | Prefijo IPv6         |
|-----------------|----------------------|
| 192.0.2.0/24    | 2001:db8:aaaa::/120  |
| 192.0.2.8/29    | 2001:db8:bbbb::/125  |

La dirección `192.0.2.9` encaja `192.0.2.8/29` mejor que `192.0.2.0/24`, de modo que será traducida como `2001:db8:bbbb::1`, no `2001:db8:aaaa::9`.

Nótese que esto crea asimetría. `2001:db8:aaaa::9` se traduce como `192.0.2.9`, lo cual se traduce como `2001:db8:bbbb::1`. Dependiendo del caso de uso, esto puede romer comunicación.

Entradas EAM superpuestas existen para ayudar a que EAM coexista con [IVI](http://www.rfc-editor.org/rfc/rfc6219.txt). Otros usos pueden emerger en el futuro.

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
