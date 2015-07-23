---
layout: documentation
title: Documentación - Instalación de los módulos de kernel
---

[Documentación](esp-doc-index.html) > [Instalación](esp-doc-index.html#instalacion) > Módulos de kernel

# Instalación de los módulos de kernel

## Indice

1. [Introducción](#introduccion)
2. [Requerimientos](#requerimientos)
	1. [`Kernels Válidos`](#kernels-soportados)
	2. [`Encabezados del Kernel`](#encabezado-kernel)
	3. [`Interfaces de Red`](#interfaces)
3. [Compilación](#compilacion)
4. [Instalación](#instalacion)

## Introducción

Jool tiene cuatro componentes:

1. Dos [Módulos de Kernel](https://es.wikipedia.org/wiki/M%C3%B3dulo_de_n%C3%BAcleo). Uno es la implementación SIIT y el otro es el Stateful NAT64. Para ser habilitados necesitan ser insertados en el kernel, y este documento explica cómo realizar esto.
2. Dos Herramientas de Configuración, una para SIIT y la otra para NAT64. Ambas son aplicaciones en el [espacio de usuario](http://es.wikipedia.org/wiki/Espacio_de_usuario). Éstas tienen su propio [documento de instalación](esp-usr-install.html).

Su forma de instalación es convencional, pero para los usuarios que no tienen experiencia previa en instalar aplicaciones que son extensiones al kernel, les servirá de gran utilidad.

## Requerimientos

### `Kernels Válidos`

Jool fue desarrollado sobre ambiente linux y lenguaje de programación "C". Para conocer la lista actualizada de kernels soportados y probados en las diferentes distribuciones de Linux [haz click aquí](esp-intro-jool.html#compatibilidad). Es factible que no vaya a haber problema alguno, al compilar Jool en versiones más recientes de kernel. ¡Ánimo, prueba y compartenos tu experiencia!

NOTA: No recomendamos usar el kernel 3.12 porque [el sistema se inhibe cuando se invoca la función icmpv6_send](https://github.com/NICMx/NAT64/issues/90).

Para validar la versión de tu kernel, usa el comando `uname -r`. Por ejemplo:

{% highlight bash %}
$ /bin/uname -r
3.5.0-45-generic
{% endhighlight %}

### `Encabezados del Kernel`

Para que Jool se compile y lige sin problemas es necesario que tu equipo cuente con los encabezados de kernel para la versión en la que te dispones a trabajar. Para ello, ejecuta el comando `apt-get install linux-headers-$(uname -r)`.

{% highlight bash %}
$ apt-get install linux-headers-$(uname -r)
{% endhighlight %}

### `Interfaces de Red`

Jool requiere al menos de una interfaz de red para poder comunicarse con los nodos via IPv6 o IPv4. Es posible usar una sola interfaz de red, con doble pila y varios protocolos, pues el kernel lo permite; sin embargo, por consideración a las personas que están incursionando en este tipo de aplicaciones se usarán ***dos interfaces de red separadas: una para IPv6 y otra para IPv4***. Y de esta manera, poder identificar más facilmente los paquetes al usar las aplicaciones de debugeo como WireShark y otros. Entonces, para validar si las interfaces de red están disponibles ejecue el comando ip link `show`. Por ejemplo:

{% highlight bash %}
$ /sbin/ip link show
(...)
2: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:3d:24:77 brd ff:ff:ff:ff:ff:ff
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:ca:18:c8 brd ff:ff:ff:ff:ff:ff
{% endhighlight %}

## Compilación

Por simplicidad, solo se distribuyen los fuentes. Para descargar Jool, hay dos opciones:

* Las versiones oficiales en nuestro sitio Web. Éstas se encuentran en la siguiente [Página de Descarga](esp-download.html).
* Las versiones en desarrollo en nuestro repositorio de GitHub. Éstas se encuentran en [Proyecto NAT64](https://github.com/NICMx/NAT64). 

Si eliges la segunda opción te sugerimos acceder el último commit de la rama principal, porque las otras ramas son para desarrollo, y están en constante cambio y no hay garantía.

Quizá estes acostumbrado a un procedimiento estándar de tres pasos para compilar e instalar programas: `./configure && make && make install`. Los módulos de kernel no tienen un script `configure`, para generar el Makefile, sino ya está hecho, entonces solo ejecuta `make` y listo.

En resumen, para compilar ambos módulos SIIT y NAT64, puedes encontrar el archivo Makefile global en la carpeta `mod`

{% highlight bash %}
user@node:~$ unzip Jool-<version>.zip
user@node:~$ cd Jool-<version>/mod
user@node:~/Jool-<version>/mod$ make
{% endhighlight %}

***Y eso es todo.***

## Instalación

El proceso de instalación consiste en copiar *los binarios generados* a *tu pool de módulos del sistema*, mediante el comando `make modules_install`:

{% highlight bash %}
user@node:~/Jool-<version>/mod# make modules_install
{% endhighlight %}

> **Advertencia!**
> 
> A partir del kernel 3.7 en Ubuntu puedes autentificar tus módulos, lo cual es una buena práctica. Te recomendamos, firmar tus modulos de kernel para asegurarte de que los estás agregando de manera responsable.
> 
> Si tu kernel NO fue configurado para _solicitar_ esta característica (los kernels de muchas distribuciones no lo hacen), no tendrás problema. Sólo ten en cuenta que cuando corras el comando `make modules_install`, se mostrará el siguiente mensaje: "Can't read private key"; esto puede parecer un error, pero de hecho es una advertencia, [así que puedes continuar la instalación](https://github.com/NICMx/NAT64/issues/94#issuecomment-45248942).
> 
> Si tu kernel _fue_ compilado para solicitar el firmado de módulos, probablemente ya sepas como llevarlo a cabo. Lo omitiremos aqui.

  Nota que, el hecho de que residan en tu pool no significa que ya hayan sido indizados, entonces, para finalizar, también necesitarás ejecutar el comando `depmod` para que se indexen los nuevos módulos:

{% highlight bash %}
user@node:~# /sbin/depmod
{% endhighlight %}

¡LISTO! Jool puede ser inicializado ahora. 

Te adelanto, los módulos serán activados usando el comando 'modprobe', aprende cómo hacerlo consultando el [Ejemplo Básico de SIIT](esp-mod-run-vanilla.html).
