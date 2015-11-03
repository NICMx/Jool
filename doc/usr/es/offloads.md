---
language: es
layout: default
category: Documentation
title: Offloads
---

[Documentación](documentation.html) > [Misceláneos](documentation.html#miscelneos) > Offloads

# Offloads

## Índice

1. Introducción
2. Offloads de recepción - ¿Qué son?
3. Offloads de recepción - El problema
4. Cómo deshacerse de Receive Offloads

## Introducción

Este documento explica offloads de recepción, su relación con Jool y la manera de quitarlos.

## Offloads de recepción - ¿Qué son?

Offloading es una técnica orientada a optimizar el rendimiento de redes que nació de la observación de que un solo paquete grande es significantemente más rapido de procesar que muchos pequeños. La idea es combinar varios paquetes de un mismo stream durante la recepción y pretender, a los ojos del resto del sistema, que el paquete resultante es el que se recibió.

Aquí hay un ejemplo. Así es como los paquetes son procesados normalmente (sin offloading):

![Fig.1 - Sin offloading](../images/offload-none.svg)

(Por el momento, el protocolo de capa de red es IPv4.)

Hay dos streams aquí. El amarillo consiste de tres paquetes pequeños:

1. 1st packet: bytes 0 through 9.
2. 2nd packet: bytes 10 to 29.
3. 3rd packet: bytes 30 to 39.

Y el azul contiene unos paquetes más grandes:

1. bytes 0 to 599
2. bytes 600 to 1199
3. bytes 1200 to 1799

Hay varias manetas de implementar receive offloads. Abajo se encuentra ilustrada una versión simplificada de lo que una NIC (interfaz de red) podría intentar, en lugar de lo de arriba:

![Fig.2 - Offloads realizados correctamente](../images/offload-right.svg)

Puesto simplemente, muchos paquetes continuos son unidos en uno equivalente. La tarjeta podría por ejemplo hacer esto uniendo fragmentos IP o incluso segmentos TCP (aunque TCP se encuentre dos capas arriba). No importa mientras el cambio sea completamente transparente en lo que a transferencia de datos se refiere.

Y sí; ahora estamos lidiando con piezas de datos más pesadas, pero a decir verdad, la mayor parte de la acitivdad de las capas de Internet y Transporte recae en los primeros bytes de cada paquete (ie. los encabezados). En general, offloading logra que se procesen n paquetes al precio de uno.

## Offloads de recepción - El problema

Una máquina que tiene que reenviar la información en lugar de consumirla tiende a romper la suposición "No importa mientras el cambio sea completamente transparente en lo que a transferencia de datos se refiere".

Por ejemplo, si el hardware tiene una [Unidad de Transmisión Máxima (MTU)](http://es.wikipedia.org/wiki/Unidad_m%C3%A1xima_de_transferencia) de 1500, esto es lo que pasa:

![Fig.3 - Offload on a router](../images/offload-router.svg)

En el paso 1 sucede agregación, que hace que el paso 2 sea muy rápido, pero el paquete ensamblado del flujo azul es demasiado grande para la interfaz de salida (tamaño 1800 > max 1500). Dependiendo de la bandera DF, esto va a resultar en fragmentación (lo cual es lento) o un tirado de paquetes (y como el origen está encendiendo DF, esto fácilmente se va a pervertir en un hoyo negro).

(En la práctica, un número de condiciones se requieren cumplir para que la NIC efectúe offloading. En ocasiones raras y aleatorias estas condiciones pueden no cumplirse, de modo que ciertos paquetes ocasionalmente no serán agregados y esquivarán el hoyo. Si el protocolo de transporte reintenta lo suficiente, en lugar de tener una denegación de servicio completa, el resultado es una red extremadamente - **EXTREMAMENTE** - lenta.)

Linux se sale con la suya (no pidiendo al administrador apagar offloads) teniendo unos cuantos hacks en la lógica de forwardeo de paquetes que se encargan de resegmentar. Jool también intenta hacer esto, pero offloading es un hack tan intrusivo que no hemos terminado de limpiarlo aún. Por esta razón, es necesario apagar offloads si el sistema los soporta y se desea utilizar a Jool.

Si Jool se está ejecutando en una máquina virtual huésped, puede ser necesario deshabilitar offloads también en la máquina host.

## Práctica

[`ethtool`](https://www.kernel.org/pub/software/network/ethtool/) parece ser la herramienta de configuración de interfaces generalmente utilizada.

{% highlight bash %}
$ sudo apt-get install ethtool
{% endhighlight %}

Es necesario aplicar lo siguiente a todas las interfaces en donde se esperan recibir paquetes necesitados de traducción:

{% highlight bash %}
$ sudo ethtool --offload [nombre de la interfaz aquí] lro off
$ sudo ethtool --offload [nombre de la interfaz aquí] gro off
{% endhighlight %}

Algunas veces ethtool indica que no es posible cambiar algunas de las variantes, y es usualmente porque no está soportada y por lo tanto no estaba encendida en primer lugar. El siguiente comando puede ser usado para observar la configuración actual.

{% highlight bash %}
$ sudo ethtool --show-offload [nombre de la interfaz aquí] | grep receive-offload
{% endhighlight %}

