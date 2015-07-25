---
layout: documentation
title: Documentación - Instalación de la Herramienta de Configuración de Jool
---

[Documentación](esp-doc-index.html) > [Instalación](esp-doc-index.html#instalacion) > Herramienta de Configuración de Jool

# Instalación de la Herramienta de Configuración de Jool

## Indice

1. [Introducción](#introduccion)
2. [Requerimientos](#requerimientos)
	1. [`Libnl-3`](#libnl-3)
	2. [`Autoconf`](#autoconf)
3. [Compilación e Instalación](#compilacion_instalacion)
	1. [`De la Web Oficial`] (#web_oficial)
	2. [`Del Repositorio GIT`] (#github)
4. [Validación] (#validacion)

## Introducción

Jool tiene cuatro componentes, es decir, cuatro ejecutables:

1. Dos [Módulos de Kernel](https://es.wikipedia.org/wiki/M%C3%B3dulo_de_n%C3%BAcleo), uno donde se implementa el Stateful NAT64, nombrado como `jool`, y el otro donde se implementa SIIT y SIIT-EAM, nombrado como `jool-siit`. 
2. Dos aplicaciones en el [espacio de usuario](http://es.wikipedia.org/wiki/Espacio_de_usuario), una para Stateful NAT64 y la otra para SIIT y SIIT-EAM, nombrados de igual manera: `jool y jool-siit` respectivamente.

En este documento abordaremos a las aplicaciones en el espacio de usuario.

Para ver detalles de los requisitos e instalación de los módulos de kernel [accese aquí](esp-mod-install.html).

## Requerimientos

### `Libnl-3`

[Este](http://www.carisma.slowglass.com/~tgr/libnl/) es el sitio oficial de libnl-3 a partir de 2014-07-31, en caso de que quieras compilar la biblioteca por tu cuenta.

Aunque si tu distribución la contiene o se puede instalar mediante las herramientas que esta proporciona, [deberias relmente aprovechar esta caracteristica en lugar de compilar la biblioteca](http://www.carisma.slowglass.com/~tgr/libnl/):

{% highlight bash %}
user@node:~# apt-get install libnl-3-dev
{% endhighlight %}

### `Autoconf`

NOTA: Se necesita autoconf ver. 2.68 o superior.

Si descargas Jool del Repositorio de Desarrollo de NICMx, te será necesario instalar la aplicación de autoconf para que se pueda generar de manera automática el script de configuración.

Para instalarlo solo requeries ejecutar lo siguiente:

{% highlight bash %}
user@node:~# apt-get install autoconf
{% endhighlight %}

## Compilación e Instalación

### `De la Web Oficial`

Si descargas la [Liberación oficial](esp-download.html)

{% highlight bash %}
user@node:~/Jool$ cd usr
user@node:~/Jool/usr$ ./configure # Requiere libnl-3
user@node:~/Jool/usr$ make
user@node:~/Jool/usr# make install
{% endhighlight %}

¡LISTO!

### `Del Repositorio GIT`

Si descargas Jool del [Repositorio de Github](https://github.com/NICMx/NAT64), ejecuta los siguientes comandos:

{% highlight bash %}
Jool$ cd usr
Jool/usr$ ./autogen.sh # Requiere autoconf 2.68 o +;
Jool/usr$ ./configure  # Requiere libnl-3
Jool/usr$ make
Jool/usr# make install
{% endhighlight %}

¡LISTO! 

## Validación

Ahora debes de ser capaz de escribir `jool --help` o `jool_siit --help` conseguir alguna salida. 

Ve a [Banderas](esp-usr-flags.html) para una documentación mas detallada.

