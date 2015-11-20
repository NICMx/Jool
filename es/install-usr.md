---
language: es
layout: default
category: Documentation
title: Aplicaciones en el Espacio de Usuario
---

[Documentación](documentation.html) > [Instalación](documentation.html#instalacin) > Aplicaciones en el Espacio de Usuario

# Instalación de las Aplicaciones de Configuración

## Índice

1. [Introducción](#introduccin)
2. [Requerimientos](#requerimientos)
	1. [Libnl-3](#libnl-3)
	2. [Autoconf](#autoconf)
3. [Obtención del código](#obtencin-del-cdigo)
4. [Compilación e Instalación](#compilacin-e-instalacin)
5. [Validación de la instalación](#validacin-de-la-instalacin)

## Introducción

Jool tiene cuatro componentes, es decir, cuatro ejecutables:

1. Dos [Módulos de Kernel](https://es.wikipedia.org/wiki/M%C3%B3dulo_de_n%C3%BAcleo). Uno de ellos (`jool_siit`) implementa SIIT y el otro (`jool`) implementa NAT64.
2. Dos aplicaciones de [espacio de usuario](http://es.wikipedia.org/wiki/Espacio_de_usuario), igualmente nombradas `jool` y `jool_siit`, que sirven para configurar a sus respectivos módulos.

Este documento explica cómo instalar las aplicaciones de espacio de usuario. Para instalar a los módulos del kernel [ver aquí](install-mod.html).

## Requerimientos

> ![Nota](../images/bulb.svg) En segmentos de código venideros:`$` indica que el comando no requiere privilegios  `#` indica necesidad de permisos.

### libnl-3

libnl, libnl-1.x y 2.x no son compatibles. Se necesita "libnl-3" versión 3.1 o superior.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Ubuntu</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
</div>

{% highlight bash %}
# apt-get install libnl-3-dev
{% endhighlight %}

{% highlight bash %}
# yum install libnl3*
{% endhighlight %}

### Autoconf

Se necesita autoconf versión 2.68 o superior.

Esta dependencia solamente es necesaria si se baja Jool desde el repositorio de Git.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Ubuntu</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
</div>

{% highlight bash %}
# apt-get install autoconf
{% endhighlight %}

{% highlight bash %}
# yum install automake
{% endhighlight %}
## Obtención del código

Existen dos opciones:

1. Releases oficiales en la [página de descarga](download.html).  
Su ventaja es que hacen más sencilla la instalación de las aplicaciones de usuario.
2. Release en desarrollo que están en el [repositorio de GitHub](https://github.com/NICMx/NAT64).  
Tiene la ventaja de que el último commit del branch master puede tener correcciones de errores menores que aún no están presentes en el último oficial.

## Compilación e Instalación

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Official release</span>
	<span class="distro-selector" onclick="showDistro(this);">Git version</span>
</div>

{% highlight bash %}
$ unzip Jool-<version>.zip
$ cd Jool-<version>/usr
$
$ ./configure
$ make
# make install
{% endhighlight %}

{% highlight bash %}
$ unzip master.zip
$ cd NAT64-master/usr
$ ./autogen.sh
$ ./configure
$ make
# make install
{% endhighlight %}

> ![Nota](../images/bulb.svg) Si solamente se desea compilar el binario SIIT, es posible agilizar la compilación corriendo los comandos `make` en la carpeta `mod/stateless`. De igual manera, si solamente se desea el NAT64, puede hacerse en `mod/stateful`.

## Validación de la instalación

{% highlight bash %}
$ jool --version
$ jool_siit --version
{% endhighlight %}

Para desplegar la ayuda sobre los parámetros configurables y desplegables de Jool se pueden usar las opciones `-?` o `--help`, de la siguiente manera:

{% highlight bash %}
$ jool --help
$ jool_siit --help
{% endhighlight %}

Alternativamente, los manuales imprimen la misma información en un formato alternativo:

{% highlight bash %}
$ man jool
$ man jool_siit
{% endhighlight %}

[Otras opciones](documentation.html#aplicacin-de-espacio-de-usuario) interactúan con el respectivo módulo, de modo que requieren que se encuentre insertado.

