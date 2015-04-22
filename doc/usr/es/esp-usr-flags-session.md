---
layout: documentation
title: Documentación - Parámetros > Session
---

[Documentación](esp-doc-index.html) > [Aplicación de espacio de usuario](esp-doc-index.html#aplicacin-de-espacio-de-usuario) > [Parámetros](esp-usr-flags.html) > \--session

# \--session

## Índice

1. [Descripción](#descripcin)
2. [Sintaxis](#sintaxis)
3. [Opciones](#opciones)
   1. [Operaciones](#operaciones)
   2. [`<protocols>`](#protocols)
   3. [`--numeric`](#numeric)
   4. [`--csv`](#csv)
4. [Ejemplos](#ejemplos)

## Descripción

Las sesiones existen mayormente para que el NAT64 decida cuando las entradas BIB deben morir. Tambien las puedes utilizar para saber exactamente quien le está hablando a tus nodos IPv6.

Cada registro BIB es un mapeo, el cual describe el nombre IPv4 de uno de tus servicios IPv6. Para cada entrada BIB, hay cero o mas registros de session, de los cuales cada uno representa una conexión activa que actualmente esta utilizando ese mapeo. 

Puedes utilizar este comando para obtener información en cada una de estas conexiones.

## Sintaxis

	jool --session [--display] [--numeric] [--csv] <protocols>
	jool --session --count <protocols>

## Opciones

### Operaciones

* `--display`: Las tablas de sesión son impresas en la salida estandar. Esta es la operación por default.
* `--count`: El número de registros por tabla de sesión es impreso en la salida estandar.

### `<protocols>`

	<protocols> := [--tcp] [--udp] [--icmp]

El comando va a operar en las tablas mencionadas aquí. Si omites esto por completo, Jool retrocederá a operar en todas sus tres tablas.


### `--numeric`

Por default, la aplicación intentará resolver los nombres de los nodos remotos hablando en cada sesión. _Si tus nameservers no están respondiendo, esto alentara la salida_.

Utiliza `--numeric` para deshabilitar este comportamiento.

### `--csv`

Por default, la aplicación va a imprimir las tablas en un formato relativamente amigable para la consola.

Utiliza `--csv` para imprimir en [formato CSV](http://es.wikipedia.org/wiki/CSV) el cual es amigable con una hoja de cálculo.

Ya que cada registro es impreso en una sola linea,  CSV es también mejor para utilizar el comando grep.

## Ejemplos

![Fig.1 - Red para ejemplo de sesión](images/usr-session.svg)

ipv6client.mx efectua dos solicitudes HTTP y un ping a example.com.

Retrocede a desplegar todos los protocolos, resolver nombres, formato consola:

{% highlight bash %}
$ jool --session
TCP:
---------------------------------
(V4_FIN_V6_FIN_RCV) Expires in 2 minutes, 57 seconds
Remote: example.com#http	ipv6client.mx#58239
Local: 192.0.2.1#60477		64:ff9b::5db8:d877#80
---------------------------------
(V4_FIN_V6_FIN_RCV) Expires in 3 minutes, 52 seconds
Remote: example.com#http	ipv6client.mx#58237
Local: 192.0.2.1#6617		64:ff9b::5db8:d877#80
---------------------------------
  (Fetched 2 entries.)

UDP:
---------------------------------
  (empty)

ICMP:
---------------------------------
Expires in 50 seconds
Remote: example.com#1402	ipv6client.mx#13371
Local: 192.0.2.1#1402		64:ff9b::5db8:d877#13371
---------------------------------
  (Fetched 1 entries.)
{% endhighlight %}

Filtra UDP e ICMP, no hace llamadas al DNS, formato consola:

{% highlight bash %}
$ jool --session --display --tcp --numeric
TCP:
---------------------------------
(V4_FIN_V6_FIN_RCV) Expires in 2 minutes, 57 seconds
Remote: 93.184.216.119#80	2001:db8::2#58239
Local: 192.0.2.1#60477		64:ff9b::5db8:d877#80
---------------------------------
(V4_FIN_V6_FIN_RCV) Expires in 3 minutes, 52 seconds
Remote: 93.184.216.119#80	2001:db8::2#58237
Local: 192.0.2.1#6617		64:ff9b::5db8:d877#80
---------------------------------
  (Fetched 2 entries.)
{% endhighlight %}

No resuelve nombres, formato CSV:

{% highlight bash %}
$ jool --session --display --numeric --csv > session.csv
{% endhighlight %}

[session.csv](obj/session.csv)

Solo muestra el numero de registros de todas las tablas:

{% highlight bash %}
$ jool --session --count
TCP: 2
UDP: 0
ICMP: 1
{% endhighlight %}
