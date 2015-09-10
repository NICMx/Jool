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
2. [Requerimientos](#requerimientos)
	1. [Kernels Válidos](#kernels-vlidos)
	2. [Paquetes básicos de compilación](#paquetes-bsicos-de-compilacin)
	2. [Encabezados del Kernel](#encabezados-del-kernel)
	3. [Interfaces de Red](#interfaces-de-red)
	4. [DKMS](#dkms)
	5. [Ethtool](#ethtool)
3. [Obtención del código](#obtencin-del-cdigo)
3. [Compilación e Instalación](#compilacin-e-instalacin)
	1. [Instalación mediante DKMS](#instalacin-mediante-dkms)
	2. [Instalación mediante Kbuild](#instalacin-mediante-kbuild)

## Introducción

Jool es cuatro binarios:

1. Dos [Módulos de Kernel](https://es.wikipedia.org/wiki/M%C3%B3dulo_de_n%C3%BAcleo) que se ligan a Linux. Uno de ellos (`jool`) implementa Stateful NAT64, el otro (`jool_siit`) implementa SIIT.  
Son los encargados de traducir paquetes.
2. Una aplicación de [Espacio de Usuario](http://es.wikipedia.org/wiki/Espacio_de_usuario) por módulo.  
Sirven para configurar a sus respectivos módulos.

Este documento se enfocará en la instalación de los módulos del kernel. La instalación de las aplicaciones de usuario tienen su [propio procedimiento](usr-install.html).

## Requerimientos

Debido a la variedad de kernels que existen, no es factible distribuir binarios de módulos de kernel, de modo que es necesario que se compilen localmente.

(En segmentos de código venideros, `$` indica que el comando no requiere privilegios; `#` indica necesidad de permisos.)

### Kernels Válidos

Jool soporta kernels de Linux a partir de la versión 3.0, y ha sido probado en varios [incrementos](intro-jool.html#compatibilidad).

El siguiente comando puede ser usado para consultar la versión del kernel actual:

{% highlight bash %}
$ /bin/uname -r
{% endhighlight %}

### Paquetes básicos de compilación

Varias distribuciones ya los incluyen; omitir este paso en esos casos.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Debian</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
	<span class="distro-selector" onclick="showDistro(this);">Arch Linux</span>
	<span class="distro-selector" onclick="showDistro(this);">openSUSE</span>
</div>

<!-- Debian -->
{% highlight bash %}
# apt-get install build-essential
{% endhighlight %}

<!-- CentOS -->
{% highlight bash %}
# yum install gcc
{% endhighlight %}

<!-- Arch Linux -->
{% highlight bash %}
# pacman -S base-devel
{% endhighlight %}

<!-- openSUSE -->
{% highlight bash %}
# zypper install gcc make
{% endhighlight %}

### Encabezados del Kernel

Son dependencia de cualquier módulo y le indican a Jool los parámetros bajo los cuales fue compilado Linux. La mayoría de las distribuciones hostean estos archivos en sus repositorios.

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Ubuntu/Debian</span>
	<span class="distro-selector" onclick="showDistro(this);">CentOS</span>
	<span class="distro-selector" onclick="showDistro(this);">openSUSE</span>
	<span class="distro-selector" onclick="showDistro(this);">Raspberry Pi</span>
</div>

<!-- Ubuntu/Debian -->
{% highlight bash %}
# apt-get install linux-headers-$(uname -r)
{% endhighlight %}

<!-- CentOS -->
{% highlight bash %}
# yum install kernel-devel
# yum install kernel-headers
{% endhighlight %}

<!-- openSUSE -->
{% highlight bash %}
# zypper install kernel-source
{% endhighlight %}

<!-- Raspberry Pi -->
{% highlight bash %}
$ # Ver https://github.com/NICMx/NAT64/issues/158
{% endhighlight %}

### Interfaces de Red

[Es posible traducir paquetes a través de una sola interfaz de red](mod-run-alternate.html), pero es más intuitivo comprender SIIT y NAT64 cuando se tienen dos: Una para IPv4 y otra para IPv6.

Por lo tanto, si se están utilizando estos documentos con fines educativos, se recomienda tener al menos dos interfaces:

{% highlight bash %}
$ ip link show
(...)
2: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:3d:24:77 brd ff:ff:ff:ff:ff:ff
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 08:00:27:ca:18:c8 brd ff:ff:ff:ff:ff:ff
{% endhighlight %}

### DKMS

DKMS es un framework que se encarga de administrar módulos. Es opcional pero recomendado (la razón se discute abajo, en la sección [Compilación e Instalación](#compilacin-e-instalacin)).

{% highlight bash %}
# apt-get install dkms
{% endhighlight %}

### Ethtool

Ethtool es una utilería para configurar las tarjetas  Ethernet, con ella se pueden visualizar y modificar sus parámetros.

{% highlight bash %}
# apt-get install ethtool
{% endhighlight %}

## Obtención del código

Existen dos opciones:

1. Releases oficiales en la [página de descarga](download.html).  
Su ventaja es que hacen más sencilla la instalación de las aplicaciones de usuario.
2. Está el [repositorio de GitHub](https://github.com/NICMx/NAT64).  
Tiene la ventaja de que el último commit del branch master puede tener correcciones de errores menores que aún no están presentes en el último oficial.

## Compilación e Instalación

Existen dos medios para instalar a Jool: Kbuild y DKMS.

Kbuild es un modo básico que simplemente se dedica a compilar e instalar el módulo para la versión actual del kernel. El Dynamic Kernel Module Support (DKMS) framework [añade la posibilidad de que el módulo se adapte a actualizaciones de Linux](https://en.wikipedia.org/wiki/Dynamic_Kernel_Module_Support) (un módulo instalado con Kbuild requiere recompilación y reinstalación cada vez que se actualiza Linux).

Para todo propósito es recomendado preferir DKMS.

### Instalación mediante DKMS

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Versión oficial</span>
	<span class="distro-selector" onclick="showDistro(this);">Versión de Github</span>
</div>

{% highlight bash %}
$ unzip Jool-<versión>.zip
# dkms install Jool-<versión>
{% endhighlight %}

{% highlight bash %}
$ unzip NAT64-master.zip
# dkms install NAT64-master
{% endhighlight %}

### Instalación mediante Kbuild

<div class="distro-menu">
	<span class="distro-selector" onclick="showDistro(this);">Versión oficial</span>
	<span class="distro-selector" onclick="showDistro(this);">Versión de Github</span>
</div>

{% highlight bash %}
$ unzip Jool-<versión>.zip
$ cd Jool-<versión>/mod
$ make
# make install
{% endhighlight %}

{% highlight bash %}
$ unzip NAT64-master.zip
$ cd NAT64-master/mod
$ make
# make install
{% endhighlight %}

> **Nota**
> 
> Por razones de seguridad, kernels 3.7 en adelante buscan que módulos instalados estén firmados.
> 
> Si el kernel no fue configurado para _requerir_ esta característica, `make install` imprimirá el mensaje "Can't read private key", lo cual es una advertencia, no un error. La instalación puede proseguir sin cambios.
> 
> Si el kernel _fue_ compilado para solicitar firmado de módulos, más burocracia (omitida aquí) es requerida.

