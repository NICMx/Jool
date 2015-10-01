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
5. [Validación](#validacin)
	1. [Versión](#versin)
	2. [Ayuda](#ayuda)
	3. [Uso](#uso)

## Introducción

Jool tiene cuatro componentes, es decir, cuatro ejecutables:

1. Dos [Módulos de Kernel](https://es.wikipedia.org/wiki/M%C3%B3dulo_de_n%C3%BAcleo), uno donde se implementa el Stateful NAT64, nombrado como `jool`, y el otro donde se implementa SIIT y SIIT-EAM, nombrado como `jool-siit`. 
2. Dos aplicaciones en el [espacio de usuario](http://es.wikipedia.org/wiki/Espacio_de_usuario), una para Stateful NAT64 y la otra para SIIT y SIIT-EAM, nombrados de igual manera: `jool y jool-siit` respectivamente.

Este documento es sobre las aplicaciones de configuración que se ejecutan en el espacio de usuario.

Para ver detalles de los requisitos e instalación de los módulos de kernel [accese aquí](mod-install.html).

## Requerimientos

![small_orange_diamond](../images/small_orange_diamond.png) En segmentos de código venideros:`$` indica que el comando no requiere privilegios  `#` indica necesidad de permisos

### Libnl-3

> **NOTA:** Libnl, libnl-1.x, 2.x no son compatibles. Se necesita Libnl-3 ver. 3.1 o superior.

Jool emplea [NETLINK](http://www.carisma.slowglass.com/~tgr/libnl/) para comunicar sus procesos de espacio de usuario con los de kernel, y viceversa.  

De preferencia no baje ni compile en forma manual la libería para evitarse problemas de ubicación y acceso a la misma.

Si su distribución reconoce a `libnl-3-dev` como un producto instalable:

{% highlight bash %}
$apt-cache show libnl-3-dev
{% endhighlight %}

Entonces, instala la libería ejecutando el siguiente comando:

{% highlight bash %}
#apt-get install libnl-3-dev
{% endhighlight %}

### Autoconf

> **NOTA:** Se necesita autoconf ver. 2.68 o superior.

Si descarga Jool del Repositorio de Desarrollo de NICMx, será necesario instalar la aplicación de autoconf para que se pueda generar de manera automática el script de configuración y los makefiles.

{% highlight bash %}
#apt-get install autoconf
{% endhighlight %}

## Obtención del código

Existen dos opciones:

1. Releases oficiales en la [página de descarga](download.html).  
Su ventaja es que hacen más sencilla la instalación de las aplicaciones de usuario.
2. Release en desarrollo que están en el [repositorio de GitHub](https://github.com/NICMx/NAT64).  
Tiene la ventaja de que el último commit del branch master puede tener correcciones de errores menores que aún no están presentes en el último oficial.

## Compilación e Instalación

Para la aplicacion de usuario se emplea Kbuild. Kbuild es un modo básico que simplemente se dedica a compilar e instalar el módulo para la versión actual del kernel.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Versión oficial</span>
	<span class="distro-selector" onclick="showDistro(this);">Versión de Github</span>
</div>

{% highlight bash %}
$ unzip Jool-<versión>.zip
$ cd Jool-<versión>/usr
$ ./configure
$ make
# make install
{% endhighlight %}

{% highlight bash %}
$ unzip NAT64-master.zip
$ cd NAT64-master/usr
$ ./autogen.sh
$ ./configure
$ make
# make install
{% endhighlight %}

## Validación

Ahora, podemos ejecutar varias acciones como: validar que versión de Jool compilamos y consultar la ayuda en línea.

### Versión

Para desplegar la versión de Jool ejecuta:

{% highlight bash %}
user@node:~/Jool/usr/$ cd stateful
user@node:~/Jool/usr/stateful$ ./jool --v
{% endhighlight %}


### Ayuda

Para desplegar la ayuda en linea sobre los parámetros configurables y desplegables de Jool puedes usar las opciones `-?` o `--help`, de la siguiente manera:

{% highlight bash %}
user@node:~/Jool/usr/stateful$ ./jool -?
{% endhighlight %}

{% highlight bash %}
user@node:~/Jool/usr/stateless$ ./jool_siit --help
{% endhighlight %}

### Uso

Para desplegar en forma resumida cuáles son las combinaciones válidas de los parámetros configurables y desplegables de Jool es con:

{% highlight bash %}
user@node:~/Jool/usr/stateless$ ./jool_siit --usage
{% endhighlight %}

Para TODAS las demás opciones se requiere habilitar previamente el servicio de traducción de paquetes como tal, es decir, haber insertado Jool en el Kernel, ya sea la modalidad stateless o stateful. Para aprender sobre ello, consulte la página de [Banderas](usr-flags.html).
