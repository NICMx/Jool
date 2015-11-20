---
language: es
layout: default
category: Documentation
title: --pool4
---

[Documentación](documentation.html) > [Aplicación de Espacio de Usuario](documentation.html#aplicacin-de-espacio-de-usuario) > `--pool4`

# \--pool4

## Índice

1. [Descripción](#descripcin)
2. [Sintaxis](#sintaxis)
3. [Argumentos](#argumentos)
   1. [Operaciones](#operaciones)
   2. [Opciones](#opciones)
4. [Ejemplos](#ejemplos)
5. [Notas](#notas)
6. [`--mark`](#mark)

## Descripción

Interactúa con el [pool de direcciones de transporte IPv4](pool4.html).

pool4 es el subconjunto de direcciones de transporte IPv4 del nodo que puede ser utilizado para traducir. 

Si pool4 está vacío, Jool tratará de enmascarar paquetes usando las direcciones (y puertos desocupados por defecto) de su propio nodo. Ver [notas](#notas).

## Sintaxis

	jool --pool4 (
		[--display] [--csv]
		| --count
		| --add <PROTOCOLOS> <prefijo-IPv4> <rango-de-puertos> [--mark <mark>] [--force]
		| --remove <PROTOCOLOS> <prefijo-IPv4> <rango-de-puertos> [--mark <mark>] [--quick]
		| --flush [--quick]
	)

	<PROTOCOLOS> := [--tcp] [--udp] [--icmp]

## Argumentos

### Operaciones

* `--display`: Lista el contenido de pool4 en salida estándar. Esta es la operación por defecto.
* `--count`: Lista el número de tablas (grupos de muestras que comparten marca y protocolo), marcas (renglones) y direcciones de transporte contenidas en el pool.
* `--add`: Forma renglones a partir de los especificado por los parámetros y los registra en pool4.
* `--remove`: Elimina de pool4 las direcciones de transporte que satisfacen los parámetros.
* `--flush`: Vacía pool4.

### Opciones

| **Bandera** | **Valor por defecto** | **Descripción** |
| `--csv` | (ausente) | Imprimir la tabla en formato [CSV](https://es.wikipedia.org/wiki/CSV). La idea es redireccionar esto a un archivo .csv. |
| `--mark` | 0 | Paquetes que contengan la marca _n_ solamente van a ser traducidos utilizando registros de pool4 que contengan la marca _n_. Ver [abajo](#mark). |
| `--tcp` | * | Si está presente, los puertos representan al protocolo TCP. |
| `--udp` | * | Si está presente, los puertos representan al protocolo UDP. |
| `--icmp` | * | Si está presente, los "puertos" representan identificadores de ICMP. |
| `<prefijo-IPv4>` | - | Dirección o grupo de direcciones siendo agregados a pool4. La longitud por defecto es 32. |
| `<rango-de-puertos>` | 1-65535 para TCP/UDP, 0-65535 para ICMP | Subconjunto de de puertos (o identificadores ICMP) de la dirección que deben ser reservados para traducción. |
| `--force` | (ausente) | Si está presente, agregar los elementos al pool incluso si son demasiados.<br />(Si no se incluye, imprimirá una advertencia y cancelará la operación.) |
| `--quick` | (ausente) | Si está presente, no se borrarán las entradas BIB que correspondan al registro pool4 siendo removido.<br />`--quick` es más rápido, no `--quick` deja la base de datos más limpia (y por lo tanto más eficiente).<br />Entradas BIB sobrantes van a ser de todos modos removidas de la base de datos una vez expiren naturalmente.<br />[Aquí](usr-flags-quick.html) hay una explicación más elaborada. |

\* `--tcp`, `--udp` e `--icmp` no son mutuamente excluyentes. Si ninguna de las tres está presente, el comando aplica a los tres protocolos.

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

Es necesario considerar que es necesario reservar los puertos de la máquina de un NAT64 para propósitos de traducción. Si sucede que algún proceso local trata de abrir un puerto en la dirección de transporte 192.0.2.1#5000 y al mismo tiempo una traducción se enmascara usando 192.0.2.1#5000, Jool va a terminar combinando la información de los dos flujos de datos.

En otras palabras, no es deseable que el dominio de puertos de pool4 intersecte con otros rangos de puertos (al igual que no se desea que rangos de puertos colisionen con otros rangos de puertos).

Un administrador ya conoce los puertos de los servicios que pueden estar estacionados en el NAT64. El otro rango que necesita considerarse es el [efímero](https://en.wikipedia.org/wiki/Ephemeral_port):

{% highlight bash %}
$ sysctl net.ipv4.ip_local_port_range 
net.ipv4.ip_local_port_range = 32768	61000
{% endhighlight %}

El rango efímero de Linux es (por defecto) 32768-61000. Por lo tanto, Jool usa 61001-65535 (de las direcciones primarias de su nodo) cuando pool4 está vacía. El primero se puede modificar mediante `sysctl -w`, y el segundo mediante `--pool4 --add` y `--pool4 --remove`.

Por ejemplo, supongamos que la máquina de Jool tiene la dirección 192.0.2.1 y pool4 está vacía.

{% highlight bash %}
$ jool --pool4 --display
  (empty)
{% endhighlight %}

Esto significa que Jool está usando los puertos 61001-65535 de la dirección 192.0.2.1. Es posible agregarlos explícitamente de la siguiente manera:

{% highlight bash %}
# jool --pool4 --add 192.0.2.1 61001-65535
# jool --pool4 --display
0	ICMP	192.0.2.1	61001-65535
0	UDP	192.0.2.1	61001-65535
0	TCP	192.0.2.1	61001-65535
  (Fetched 3 samples.)
{% endhighlight %}

Si solo se tiene esta dirección, pero se desean reservar más puertos para traducción, es necesario robarlos de otros rangos. El efímero es un buen candidato:

{% highlight bash %}
# sysctl -w net.ipv4.ip_local_port_range="32768 40000"
# jool --pool4 --add 192.0.2.1 40001-61000
$ sysctl net.ipv4.ip_local_port_range 
net.ipv4.ip_local_port_range = 32768	40000
$ jool --pool4 --display
0	ICMP	192.0.2.1	40001-65535
0	UDP	192.0.2.1	40001-65535
0	TCP	192.0.2.1	40001-65535
  (Fetched 3 samples.)
{% endhighlight %}

> ![Advertencia](../images/warning.svg) Jool no es capaz de confirmar que pool4 no intersecte con otros rangos de puertos; esta validación cae a responsabilidad del operador.

## `--mark`

Todos los paquetes en Linux cargan un valor numérico (llamado "marca") que puede ser definido por el operador. Jool utiliza este valor para asignar diferentes entradas de pool4 a diferentes clientes de IPv6.

Entradas de pool4 que contengan la marca _n_ solamente van a servir paquetes que contengan la marca _n_. Mediante matching de iptables durante prerouting, es posible basar la marca en diversos parámetros.

Por ejemplo:

![Fig. 1 - Diagrama para marcas](../images/network/pool4-mark.svg)

Paquetes de la red 2001:db8:1::/64 van a ser enmascarados usando solo los puertos 10000-19999:

{% highlight bash %}
# jool --pool4 --add 192.0.2.1 10000-19999 --mark 10
# ip6tables -t mangle -I PREROUTING -s 2001:db8:1::/64 -j MARK --set-mark 10
{% endhighlight %}

y paquetes de la red 2001:db8:2::/64 van a ser enmascarados usando solo los puertos 20000-29999:

{% highlight bash %}
# jool --pool4 --add 192.0.2.1 20000-29999 --mark 20
# ip6tables -t mangle -I PREROUTING -s 2001:db8:2::/64 -j MARK --set-mark 20
{% endhighlight %}

Reconocer a clientes de IPv6 detrás de entradas pool4 específicas ayuda a crear ACLs y también prevenir que grupos de clientes causen ataques DoS malgastando todos los puertos de pool4.

