---
layout: documentation
title: Documentación - Instalación de las Aplicaciónes Modo Usuario
---

[Documentación](esp-doc-index.html) > [Instalación](esp-doc-index.html#instalacion) > Aplicaciones en espacio de usuario

# Instalación de las aplicaciones en espacio de usuario

## Introducción

Jool es cuatro cosas:

1. Dos [modulos de kernel](https://es.wikipedia.org/wiki/M%C3%B3dulo_de_n%C3%BAcleo) que se pueden añadir a Linux. Uno de ellos es la implementación SIIT y el otro es un Stateful NAT64. Estos tienen su propio [documento de instalación](esp-mod-install.html).
2. Dos aplicaciones en [espacio de usuario](http://es.wikipedia.org/wiki/Espacio_de_usuario) que pueden ser utilizadas para configurar cada uno de los modulos.

Este documento explica como obtener los binarios de las aplicaciones en espacio de usuario.

## Si descargas la [Liberación oficial](esp-download.html)

{% highlight bash %}
user@node:~/Jool$ cd usr
user@node:~/Jool/usr$ ./configure # Se necesita libnl-3 para ejecutar esto; ver abajo.
user@node:~/Jool/usr$ make
user@node:~/Jool/usr# make install
{% endhighlight %}

Listo; ahora debes de ser capaz de escribir `jool --help` o `jool_siit --help` conseguir alguna salida. Ve a [Banderas](esp-usr-flags.html) para una documentación mas detallada.

## Si descargas Jool del [Repositorio de Github](https://github.com/NICMx/NAT64)

El repositorio no mantiene un seguimiento del script de configuración, asi que lo tienes que generar por tu cuenta. Se necesita autoconf 2.68 o una versión superior a esa.

{% highlight bash %}
user@node:~# apt-get install autoconf
{% endhighlight %}

Despues solo agregale al procedimiento normal de instalación una llamada a `autogen.sh`:

{% highlight bash %}
Jool$ cd usr
Jool/usr$ ./autogen.sh # Se necesita autoconf 2.68 o una versión superior para ejecutar esto.
Jool/usr$ ./configure # Se necesita libnl-3 para ejecutar esto; ver abajo.
Jool/usr$ make
Jool/usr# make install
{% endhighlight %}

Listo; ahora debes de ser capaz de escribir `jool --help` o `jool_siit --help` conseguir alguna salida. Ve a [Banderas](esp-usr-flags.html) para una documentación mas detallada.

## libnl-3

[Este](http://www.carisma.slowglass.com/~tgr/libnl/) es el sitio oficial de libnl-3 a partir de 2014-07-31, en caso de que quieras compilar la biblioteca por tu cuenta.

Aunque si tu distribución la contiene o se puede instalar mediante las herramientas que esta proporciona, [deberias relmente aprovechar esta caracteristica en lugar de compilar la biblioteca](http://www.carisma.slowglass.com/~tgr/libnl/):

{% highlight bash %}
user@node:~# apt-get install libnl-3-dev
{% endhighlight %}
