---
layout: documentation
title: Documentación - Mapeos Estáticos
---

[Documentación](esp-doc-index.html) > [Ejemplos de uso](esp-doc-index.html#ejemplosdeuso) > [Stateful NAT64](esp-mod-run-stateful.html) > Mapeos Estáticos

# Mapeos Estáticos

Cuando sucede una traducción de IPv6 a IPv4, queda muy poco de los headers del paquete original. Por esto, Jool tiene que recordar quien intentó hablar con quien y en que puertos, para que cuando la respuesta llegue, poder deducir a que conversación pertenece el paquete, y modifique los headers correctamente. Esto no es solo un capricho del Stateful NAT64; le Stateful NAT tradicional tambien lo hace. 

La base de datos en la que estan almacenados los mapeos se llama BIB ([Binding Information Base](esp-misc-bib.html)) por sus siglas en inglés. Cada registro en la base de datos contiene una dirección IPv4 _A_ y su puerto _b_, y una dirección IPv6 _C_ y su puerto _d_. El registro básicamente dice, "Si un paquete hacia la dirección _A_ en el puerto _b_ llega, traducelo y redireccionalo a la dirección _C_ en el puerto _d_".


Por que necesitas saber eso?. Una instalación básica de una Stateful NAT64 le dará a tu red IPv6 acceso a tu Internet IPv4 promedio, pero es un poco o muy molesto que los nodos IPv4 no puedan hablar con los nodos IPv6 sin que los últimos hayan iniciado las conversaciónes. De cualquier manera, NAT64 hereda de NAT la habilidad de configurar mapeos manuales entre nodos internos y externos("[Redireccionameiento de puertos](http://en.wikipedia.org/wiki/Port_forwarding)"). Si quieres poner como ejemplo, publicar un servidor en tu red IPv6 para que losd nodos IPv4 lo vean, entonces tendras que dar de alata manualmente un registro BIB en la base de datos.

![Fig.1 - Diseño de la red](images/static-network.svg)

Asi que lo que tenemos es, los nodos IPv6 pueden ver a un servidor HTTP mandando una solicitud a 1::1 en el puerto 80. lo que queremos es hacerlo visible al exterior mediante la dirección 1.2.3.4 en el puerto 5678 (Usaremos un puerto diferente simplemente por que podemos).

Para crear un mapeo, tienes que solicitarle a la [aplicación de espacio de usuario](esp-usr-install.html) algo en estas lineas:

	$ jool --bib --add <protocols> <Ipv6 address>#<"IPv6" port> <IPv4 address>#<"IPv4" port>

el cual en nuestro ejemplo sera traducido a:

	$ jool --bib --add --tcp 1::1#80 1.2.3.4#5678

> Si te manda un error, ejecuta `dmesg` para conocer la causa. Muy probablemente estas usando una dirección IPv4 que no agregaste al pool. Agrega la dirección de esta manera:
> 
> 	$ jool --pool4 --add 1.2.3.4
> 
> Luego intenta de nuevo la inserción del mapeo.

Y diviertete.

![Fig.2 - Test](images/static-hiya.png)

Ejecuta una versión no operativa del comando `--bib` para mostrar tu base de datos actual:

	$ jool --bib
	TCP:
	[Static] 1.2.3.4#5678 - 1::1#80
	  (Fetched 1 entries.)
	UDP:
	  (empty)
	ICMP:
	  (empty)

Si la salida muestra una tabla mas poblada, es por que Jool ha estado traduciendo trafico. Mapeos estáticos (manuales) y dinámicos(creados por Jool) pertenecen a la misma base de datos.

Ten en cuenta que no hay solo una, sino tres tablas BIB diferentes. Agregamos el registro solo al BIB TCP por que utilizamos el parámetro `--tcp`.

	$ # Add an entry to the UDP BIB
	$ jool --bib --add --udp 1::1#80 1.2.3.4#5678
	$ # Add an entry to the TCP and ICMP BIBs
	$ jool --bib --add --udp --icmp 1::1#80 1.2.3.4#5678
	$ # Show the three tables.
	$ jool --bib --tcp --udp --icmp
	$ # Show the three BIBs, quick version.
	$ jool --bib
	$ # (We didn't include any protocols, so Jool assumed we wanted to show every table.)

"Aguarda!", te escucho gritar. "El protocolo ICMP no usa puertos!". Pero utiliza identificadores ICMP, los cuales son muy similares. Sin embargo no tiene mucho sentido crear mapeos ICMP manuales,  ya que los identificadores ICMP son frecuentemente impredecibles (a diferencia de los puertos de destino).

Si necesitas remover el mapeo, reemplaza "add" por "remove" y especifica cualquier lado de la ecucación (Los mapeos son únicos en ambos lados):

{% highlight bash %}
$ jool --bib --remove --tcp 1::1#80
or
$ jool --bib --remove --tcp 1.2.3.4#5678
or
$ # This won't hurt you (and will make sure you're removing exactly what you want to remove).
$ jool --bib --remove --tcp 1::1#80 1.2.3.4#5678
{% endhighlight %}
