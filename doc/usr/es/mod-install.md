---
language: es
layout: default
category: Documentation
title: Instalación del Servidor Jool
---

[Documentación](documentation.html) > [Instalación](documentation.html#instalacin) > Servidor Jool

# Instalación del Servidor Jool

## Índice

1. [Introducción](#introduccin)
2. [Requerimientos](#requerimientos)<br />
	a) [Kernels Válidos](#kernels-vlidos)<br />
	b) [Encabezados del Kernel](#encabezados-del-kernel)<br />
	c) [Interfaces de Red](#interfaces-de-red)<br />
	d) [Ethtool](#ethtool)
3. [Baja, Compila e Instala](#baja-compila-e-instala)<br />
	a) [De la Web Oficial](#de-la-web-oficial)<br />
	b) [Del Repositorio GIT](#del-repositorio-git)
4. [Genera Archivo de Dependencias](#genera-archivo-de-dependencias)

## Introducción

Jool tiene cuatro componentes, es decir, cuatro ejecutables:

1. Dos [Módulos de Kernel](https://es.wikipedia.org/wiki/M%C3%B3dulo_de_n%C3%BAcleo), uno donde se implementa el Stateful NAT64, nombrado como `jool`, y el otro donde se implementa SIIT y SIIT-EAM, nombrado como `jool-siit`.
2. Dos aplicaciones en el [Espacio de Usuario](http://es.wikipedia.org/wiki/Espacio_de_usuario),  una para Stateful NAT64 y la otra para SIIT y SIIT-EAM, nombrados de igual manera: `jool y jool-siit` respectivamente.

En este documento nos enfocaremos a los primeros dos módulos del kernel, o sea, a las aplicaciones principales para habilitar uno u otro servicio. Para activar la traducción de paquetes se requiere insertar los módulos en el kernel. Continúe leyendo este documento, si quiere conocer cuáles son los requisitos y su procedmiento.

La instalación de los Módulos del Kernel es convencional, pero para los usuarios que no tienen experiencia previa en instalar aplicaciones que son extensiones al kernel, les podrá ser de gran utilidad.

Las aplicaciones en el espacio de usuario son para configuración de Jool, la explicación de cómo instalarlas se encuentra en una [página aparte](usr-install.html).

## Requerimientos

### Kernels Válidos

Jool fue desarrollado sobre ambiente linux y lenguaje de programación "C". Para conocer la lista actualizada de kernels soportados y probados en las diferentes distribuciones de Linux [haz click aquí](intro-jool.html#compatibilidad). Es factible que no vaya a haber problema alguno, al compilar Jool en versiones más recientes de kernel. ¡Ánimo, prueba y compartenos tu experiencia!

NOTA: No recomendamos usar el kernel 3.12 porque [el sistema se inhibe cuando se invoca la función icmpv6_send](https://github.com/NICMx/NAT64/issues/90).

Para verificar la versión de tu kernel, usa el siguiente comando:

{% highlight bash %}
$ /bin/uname -r
{% endhighlight %}

### Encabezados del Kernel

Para que Jool se compile y lige sin problemas es necesario que tu equipo cuente con los encabezados de kernel para la versión en la que te dispones a trabajar. Para ello, ejecuta con permisos de administrador lo siguiente:

{% highlight bash %}
user@node# apt-get install linux-headers-$(uname -r)
{% endhighlight %}

### Interfaces de Red

Jool requiere al menos de una interfaz de red para poder comunicarse con los nodos via IPv6 e IPv4. Esto es posible, al habilitar una sola interfaz de red, con doble pila y varios protocolos, pues el kernel lo permite; sin embargo, por consideración a las personas que están incursionando en este tipo de aplicaciones se usarán `dos interfaces de red separadas: una para IPv6 y otra para IPv4`. Y de esta manera, poder identificar más facilmente los paquetes al usar las aplicaciones de debugeo como WireShark y otros. Entonces, para validar cuáles y cuántas interfaces de red están disponibles ejecuta lo siguiente:

{% highlight bash %}
$ ip link show
(...)
2: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:3d:24:77 brd ff:ff:ff:ff:ff:ff
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:ca:18:c8 brd ff:ff:ff:ff:ff:ff
{% endhighlight %}

### Ethtool

Ethtool es una utilería para configurar las tarjetas  Ethernet, con ella se pueden visualizar y modificar sus parámetros. Para instalarla ejecuta con permisos de administrador:

{% highlight bash %}
user@node# apt-get install ethtool
{% endhighlight %}

## Baja, Compila e Instala

Por simplicidad, solo se distribuyen los fuentes. Para descargar Jool, hay dos opciones:

* Las versiones oficiales de Jool en nuestro Sitio Web. Éstas se encuentran en la [Página de Descarga](download.html).
* Las versiones en desarrollo en nuestro Repositorio de GitHub. Éstas se encuentran en [Proyecto NAT64](https://github.com/NICMx/NAT64). 

Existen algunas pequeñas variantes al bajarlo de un portal u otro, no tan solo de nombre, sino de contenido.

Quizá estes acostumbrado a un procedimiento estándar de tres pasos para compilar e instalar programas: `./configure && make && make install`. Los módulos de kernel no vienen con un script `configure`, para generar el Makefile, sino ya está hecho, por lo que solo se requiere ejecutar los últimos dos pasos.

### De la Web Oficial

Si buscas la versión más estable o versiónes anteriores de Jool, entonces descárgalo desde este mismo portal, dirigiendote a la [página de Descarga](download.html). Sigue estos pasos:

1) Elige la versión

2) Elige el formato (zip, sha, md5)

3) Descarga el archivo comprimido

4) Descomprime

![small_orange_diamond](../images/small_orange_diamond.png) Asumiendo que lo bajastes en formato ZIP, en la carpeta de _Downloads_ y lo quieres colocar en _Desktop_, ejecuta los siguientes comandos:

{% highlight bash %}
user@node:$ cd Downloads
user@node:~/Downloads$ unzip Jool-<version>.zip -d ../Desktop
{% endhighlight %}
 
5) Compila ambos módulos SIIT y NAT64

{% highlight bash %}
user@node:~$ cd ../Desktop/Jool-<version>/mod
user@node:~/Desktop/Jool-<version>/mod$ make
{% endhighlight %}

6) Instala

El proceso de instalación consiste en copiar `los binarios generados`  a  `tu pool de módulos del sistema`. Empleando permisos de administrador ejecuta:

{% highlight bash %}
user@node:~/Jool-<version>/mod# make modules_install
{% endhighlight %}

### Del Repositorio GIT

Si descargas Jool del [Repositorio de Github](https://github.com/NICMx/NAT64), te sugerimos acceder el último commit de la rama principal, porque las otras ramas son para desarrollo, y están en constante cambio y no hay garantía. Sigue estos pasos:

1) Elige la rama "master"

2) Selecciona el icono `Download ZIP`

3) Descarga

4) Descomprime

![small_orange_diamond](../images/small_orange_diamond.png) Asumiendo que se descargó en _Downloads_ y lo quieres colocar en _Desktop_, ejecuta los siguientes comandos:

{% highlight bash %}
user@node:$ cd Downloads
user@node:~/Downloads$ unzip NAT64-<version>.zip -d ../Desktop
{% endhighlight %}
 
5) Compila ambos módulos SIIT y NAT64

{% highlight bash %}
user@node:~$ cd ../Desktop/NAT64-<version>/mod
user@node:~/Desktop/NAT64-<version>/mod$ make
{% endhighlight %}

6) Instala

El proceso de instalación consiste en copiar `los binarios generados`  a  `tu pool de módulos del sistema`. Empleando permisos de administrador ejecuta:

{% highlight bash %}
user@node:~/NAT64-<version>/mod# make modules_install
{% endhighlight %}

## Genera Archivo de Dependencias

El hecho de que residan en la pool no significa que ya hayan sido indizados, entonces, para finalizar, también necesitarás indexar los nuevos módulos. Ejecuta aqui también con permisos de administrador el comando:

{% highlight bash %}
user@node:~# depmod
{% endhighlight %}

Mediante el comando **depmod** se genera el archivo de dependencias *Makefile* que usará **modprobe** para cargar los módulos, aprende cómo hacerlo consultando [el ejemplo básico de SIIT](mod-run-vanilla.html).

![thumbsup](../images/thumbsup.png) Jool puede ser inicializado ahora. 

> **ADVERTENCIA :**<br />
>
> A partir del **kernel 3.7** en Ubuntu puedes autentificar tus módulos, lo cual es una buena práctica. Te recomendamos, firmar tus modulos de kernel para asegurarte de que los estás agregando de manera responsable.
> Si tu kernel NO fue configurado para _solicitar_ esta característica no tendrás problema. Los kernels de muchas distribuciones no lo hacen. Solo ten en cuenta que cuando corras el comando `make modules_install`, se mostrará el siguiente mensaje: **"Can't read private key"**; esto puede parecer un error, pero de hecho es una advertencia, [así que puedes continuar la instalación](https://github.com/NICMx/NAT64/issues/94#issuecomment-45248942).
> Si tu kernel _fue_ compilado para solicitar el firmado de módulos, probablemente ya sepas como llevarlo a cabo. **Nota:** Lo omitiremos aquí.
