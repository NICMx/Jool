---
layout: documentation
title: Documentación - Instalación de los módulos de kernel
---

[Documentación](esp-doc-index.html) > [Instalación](esp-doc-index.html#instalacion) > Módulo de kernel

# Instalación de los módulos de kernel

## Indice

1. [Introducción](#introduccion)
2. [Requerimientos](#requerimientos)
3. [Compilación](#compilacion)
4. [Instalación](#instalacion)

## Introducción

Jool is four things:

1. Dos [modulos de kernel](https://es.wikipedia.org/wiki/M%C3%B3dulo_de_n%C3%BAcleo) que se pueden añadir a Linux. Uno de ellos es la implementación SIIT y el otro es un Stateful NAT64. They are the main components and all you need to get started; this document explains how to install them.
2. Dos aplicaciones en [espacio de usuario](http://es.wikipedia.org/wiki/Espacio_de_usuario) que pueden ser utilizadas para configurar cada uno de los modulos. Estas tienen su propio [documento de instalación](esp-usr-install.html).

Cuando lo planteas de esa manera, realmente no hay nada inusual en la instalación de Jool. Pero supongo que algunos de nuestros usuarios pueden no tener experiencia previa entrometiendose con drivers, asi que esta descripción generar servira como introducción para por lo menos darles una idea de lo que sucede en cada paso.

## Requerimientos

Primero que nada, la computadora que va a estar traduciendo el tráfico necesita un kernel (de nuevo, Linux) cuya version entre 3.0 y 3.15. Versiones mas recientes probablemente se comporten bien, pero no las hemos probado. No recomendamos usar Linux 3.12 por las razones indicadas [aquí](https://github.com/NICMx/NAT64/issues/90).

Usa el comando `uname -r` para ver la versión de tu kernel.

{% highlight bash %}
$ /bin/uname -r
3.5.0-45-generic
$ # OK, fine.
{% endhighlight %}

Si apenas te estás familiarizando con la traducción IPv4/IPv6, algunas visualizan de una mejor manera su funcionamiento y sufren menos cuando el traductor tiene dos interfaces de red separadas (una para interactuar con redes IPv6, y otra con redes IPv4). Esto no es un requisito; se puede trabajar con una sola interfaz (manejando una pila doble), y tambien puedes tener mas de una por protocolo. Esto es posible por que deducir por medio de cual interfaz deberia de ser enviado un paquete es un problema de ruteo, el cual ya está bien implementado en el kernel.

Ya que los tutoriales son en primer lugar y mas que nada una herramienta para poner a los recién llegados en el contexto correcto, la mayor parte de la discusión sobre deployment asumirá dos interfaces separadas. (ejemplificadas abajo: eth0 and eth1).

{% highlight bash %}
$ /sbin/ip link show
(...)
2: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:3d:24:77 brd ff:ff:ff:ff:ff:ff
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:ca:18:c8 brd ff:ff:ff:ff:ff:ff
{% endhighlight %}

Finalmente, necesitas tus encabezados de kernel. Si estás usando apt-get, sólo ejecuta esto:

{% highlight bash %}
$ apt-get install linux-headers-$(uname -r)
{% endhighlight %}

## Compilación

Cada versión del kernel combinada con arquitecturas diferentes requiere binarios diferentes, asi que proveer paquetes para cada combinación sería imposible. Por esta razón, lo que vas a descargar sera el código; no hay forma de evitar que tengas que compilar el código tu mismo.

Por otro lado, los módulos de kernel solo pueden tener como dependencias a los encabezados de kernel y un buen compilador, así que el procedimiento es bastante ligero.

Para descargar Jool, tienes dos opciones:

* Las versiones oficiales se encuentran en la [Págins de Descarga](esp-download.html). Esto resultara menos complejo cuando estés instalando la aplicación de espacio de usuario.
* Está el [Repositorio de Github](https://github.com/NICMx/NAT64). Quizá haya leves correcciones de bugs que no están presentes en la última versión oficial, a la cual puedes acceder dirigiendote al último commit de la rama principal (En caso de que te preguntes, hacemos el desarrollo riesgoso en otra parte).

Quizá estes acostumbrado a un procedimiento estándar de tres pasos para compilar e instalar programas: `./configure && make && make install`. Los módulos de kernel no lo siguen, sino que tienen un procedimiento propio muy especial.

En lo que a compilación respecta, no hay script `configure`. Pero tampoco tienes que editar el archivo Makefile; te diriges directo a ejecutar `make` y has acabado. Puedes encontrar el archivo Makefile global en la carpeta `mod`:

{% highlight bash %}
user@node:~$ unzip Jool-<version>.zip
user@node:~$ cd Jool-<version>/mod
user@node:~/Jool-<version>/mod$ make
{% endhighlight %}

Y eso es todo.

## Instalación

Copias los binarios generados a tu pool de modulos del sistema ejecutando el comando `modules_install` target:

{% highlight bash %}
user@node:~/Jool-<version>/mod# make modules_install
{% endhighlight %}

> **Advertencia!**
> 
> Desde el kernel 3.7 en adelante seria conveniente que firmaras tus modulos de kernel para asegurarte de que los estas agregando de manera responsable.
> 
> Pero si tu kernel no fue configurado para _solicitar_ esta carácteristica (los kernels de muchas distribuciones no lo hacen), no tendras mucho problema aquí. La salida de `make modules_install` mostrará el mensaje "Can't read private key"; esto puede parecer un error, pero de hecho es una advertencia, [así que puedes continuar la instalación pacificamente](https://github.com/NICMx/NAT64/issues/94#issuecomment-45248942).
> 
> Lo siento; si tu kernel _fue_ compilado para solicitar el firmado de módulos, probablemente sepas lo que estas haciendo, así que voy a omitir las instrucciones para hacerlo funcionar.

 Despues activarás los módulos usando el comando 'modprobe'. La cuestion es que, el hecho de que residan en tu pool no significa que ya hayan sido indizados. Utiliza `depmod` para hacer que `modprobe` sepa que fueron incluidos nuevos módulos:

{% highlight bash %}
user@node:~# /sbin/depmod
{% endhighlight %}

Listo; Jool puede ser inicializado ahora. Lógicamente el siguiente paso es el [Ejemplo Básico de SIIT](esp-mod-run-vanilla.html).
