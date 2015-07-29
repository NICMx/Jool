---
layout: documentation
title: Documentación - Instalación de la Herramienta de Configuración de Jool
---

[Documentación](esp-doc-index.html) > [Instalación](esp-doc-index.html#instalacion) > Herramienta de Configuración de Jool

# Instalación de la Herramienta de
Configuración de Jool

## Indice

1. [Introducción](#introduccion)
2. [Requerimientos](#requerimientos)
	1. [`Libnl-3`](#libnl-3)
	2. [`Autoconf`](#autoconf)
3. [Compilación e Instalación](#compilacion_instalacion)
	1. [`De la Web Oficial`] (#web_oficial)
	2. [`Del Repositorio GIT`] (#github)
4. [Validación] (#validacion)
	1. [Versión] (#version)
	2. [Ayuda] (#ayuda)
	3. [Uso] (#uso)

## Introducción

Jool tiene cuatro componentes, es decir, cuatro ejecutables:

1. Dos [Módulos de Kernel](https://es.wikipedia.org/wiki/M%C3%B3dulo_de_n%C3%BAcleo), uno donde se implementa el Stateful NAT64, nombrado como `jool`, y el otro donde se implementa SIIT y SIIT-EAM, nombrado como `jool-siit`. 
2. Dos aplicaciones en el [espacio de usuario](http://es.wikipedia.org/wiki/Espacio_de_usuario), una para Stateful NAT64 y la otra para SIIT y SIIT-EAM, nombrados de igual manera: `jool y jool-siit` respectivamente.

En este documento abordaremos a las aplicaciones en el espacio de usuario.

Para ver detalles de los requisitos e instalación de los módulos de kernel [accese aquí](esp-mod-install.html).

## Requerimientos

### `Libnl-3`

> **NOTA: Libnl, libnl-1.x, 2.x no son compatibles. Se necesita Libnl-3 ver. 3.1 o superior.**

Jool emplea [NETLINK] (http://www.carisma.slowglass.com/~tgr/libnl/) para comunicar sus procesos de espacio de usuario con los de kernel, y viceversa.  

De preferencia no bajes y compiles en forma manual la libería para evitarte problemas de ubicación y acceso a la misma.

Si tu distribución reconoce a `libnl-3-dev` como un producto instalable:

{% highlight bash %}
user@node:~$apt-cache show libnl-3-dev
{% endhighlight %}

Entonces, instalala ejecutando el siguiente comando con permisos de administrador:

{% highlight bash %}
user@node:~#apt-get install libnl-3-dev
{% endhighlight %}

### `Autoconf`

> **NOTA: Se necesita autoconf ver. 2.68 o superior.**

Si descargas Jool del Repositorio de Desarrollo de NICMx, te será necesario instalar la aplicación de autoconf para que se pueda generar de manera automática el script de configuración y los makefiles. Para llevarlo a cabo la instalación hazlo con permisos de administrador:

{% highlight bash %}
user@node:~#apt-get install autoconf
{% endhighlight %}

## Compilación e Instalación

### `De la Web Oficial`

Si descargas Jool de la [Web Oficial](esp-download.html), ejecuta los siguientes comandos:

NOTA: Observa que para ejecutar exitosamente el `make install` necesitarás el acceso de administrador.

{% highlight bash %}
user@node:~/Jool$ cd usr
user@node:~/Jool/usr$ ./configure
user@node:~/Jool/usr$ make
user@node:~/Jool/usr# make install
{% endhighlight %}

### `Del Repositorio GIT`

Si descargas Jool del [Repositorio de Github](https://github.com/NICMx/NAT64), ejecuta los siguientes comandos:

NOTA: Observa que para ejecutar exitosamente el `make install` necesitarás el acceso de administrador.
 
{% highlight bash %}
Jool$ cd usr
Jool/usr$ ./autogen.sh
Jool/usr$ ./configure
Jool/usr$ make
Jool/usr# make install
{% endhighlight %}

## Validación

Ahora, podemos ejecutar varias acciones como: validar que versión de Jool compilamos y consultar la ayuda en línea.

### `Versión`

Para desplegar la versión de Jool ejecuta:

{% highlight bash %}
user@node:~/Jool/usr/$ cd stateful
user@node:~/Jool/usr/stateful$ ./jool --v
{% endhighlight %}


### `Ayuda`

Para desplegar la ayuda en linea sobre los parámetros configurables y desplegables de Jool puedes usar las opciones `-?` o `-help`, de la siguiente manera:

{% highlight bash %}
user@node:~/Jool/usr/stateful$ ./jool -?
{% endhighlight %}

### `Uso`

Para desplegar en forma resumida cuáles son las combinaciones válidas de los parámetros configurables y desplegables de Jool es con:

{% highlight bash %}
user@node:~/Jool/usr/stateless$ ./jool_siit --usage
{% endhighlight %}

Para TODAS las demás opciones se requiere habilitar previamente el servicio de traducción de paquetes como tal, es decir, haber insertado Jool en el Kernel, ya sea la modalidad stateless o stateful. Para aprender sobre ello, consulte la página de [Banderas](esp-usr-flags.html).
