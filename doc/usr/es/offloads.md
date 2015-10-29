---
language: es
layout: default
category: Documentation
title: Offloading
---

[Documentación](documentation.html) > [Otros](documentation.html#otros) > Offloading

# Offload

## Índice

1. [Teoría](#teoria)
2. [Práctica](#practica)

## Teoría

Offloading es una técnica orientada a optimizar el rendimiento de la red. Nació de la observación de que un solo paquete grande es significantemente más rapido de procesar que muchos pequeños, la idea es combinar muchos de ellos 


Offloading is a technique meant to optimize network throughput. Born from the observation that a single large packet is significantly faster to process than several small ones, the idea is to combine several of them from a common stream on reception, and then pretend, to the eyes of the rest of the system, that the new packet was the one received from the cord all along.


Aquí tenemos un ejemplo visual. Así es como los paquetes son procesados normalmente (sin offloading):

![Fig.1 - No offload](../images/offload-none.svg)

(Por el momento, asume que la capa de Internet soporta IPv4.)

Hay dos streams aquí. El amarillo consiste de tres paquetes muy pequeños:

1. 1st packet: bytes 0 through 9.
2. 2nd packet: bytes 10 to 29.
3. 3rd packet: bytes 30 to 39.

Y el azul contiene unos paquetes más largos:

1. bytes 0 to 599
2. bytes 600 to 1199
3. bytes 1200 to 1799

Hay muchas manetas de implementar offloading. Abajo se encuentra ilustrada una versión simplificada de lo que una NIC(interfáz de red) quizá podria hacer, en lugar de lo de arriba:

![Fig.2 - Offload done right](../images/offload-right.svg)

Simplemente poner, muchos paquetes continuos 

Puesto simplemente, muchos paquetes continuos son unidos en uno equivalente y mas grande. La tarjeta podria por ejemplo hacer esto uniendo fragmentos IP o incluso segmentos TCP (aunque TCP se encuentre 2 capas arriba). No importa mientras el cambio sea completamente transparente por lo menos en lo que a transferencia de datos se refiere. 

Y si, ahora estamos lidiando con piezas de datos más pesadas, pero a decir verdad, la mayor parte de la acitivdad de las capas de Internet y Transporte recae en los primeros bytes de cada paquete (ej. los encabezados). Asi que mayormente conseguimos procesar n paquetes por el precio de uno.


Esto esta excelente, pero empiezas a tener problemas en caso de que el sistema tenga que redireccionar los datos (en lugar de comsumirlos). Digamos el hardware tiene una [Unidad de Transmisión Máxima (MTU)](http://es.wikipedia.org/wiki/Unidad_m%C3%A1xima_de_transferencia) de 1500; esto es lo que pasa:

![Fig.3 - Offload on a router](../images/offload-router.svg)

En el paso 1 sucede la agregación, lo que hace le paso 2 muy rápido, pero como el paquete ensamblado del flujo de datos azul es muy grande para la interfaz de salida (tamaño 1800 > max 1500), el paquete se fragmenta en el paso 3, lo cual es ineficiente.

Mas importante, si el emisor realizó un [path MTU discovery](http://en.wikipedia.org/wiki/Path_MTU_Discovery), entonces el MTU óptimo computado se perderá en el paso 1 (por que no esta almanecado en el paquete; es indicado por su tamaño, el cual es modificado por el paso1). Por que el parámetro "Don't Fragment" del paquete estará encendido, entonces el paquete eventualmente e irremediablemente sera desechado tan pronto llegue a un MTU menor. Por lo tanto, hemos creado un hoyo negro.

(Bueno, no completamente. Un cierto numero de condiciones son requeridas por la Interfaz de red(NIC) para ejecutar el offloading. Puede que en algunas ocasiones raras y aleatorias estas condiciones no se cumplan, asi que ciertos paquetes ocasionalmente no serán agregados, y asi evitan el hoyo. Si tu protocolo de transporte reintenta suficientemente, en lugar de tener una denegación de servicio completa, tienes una red extrema - **EXTREMAMENTE** - lenta.)

Cuando la maquina de redireccionamiento es un router IPv6 (o, en el caso de Jool, un SIIT/NAT64 traduciendo de IPv4 a 6), esto es un problema mas inmediato por que los _routers IPv6 no estan pensados para fragmentar paquetes_  (se espera que solo desechen el paquete y devuelvan un mensaje de error ICMP). Así que tu paquete se perdera en el paso 3 _incluso si el parámetro "Don't Fragment" del paquete original no fue indicado_.

Si estas ejecutando Jool en una maquina virtual huesped, algo importante que debes mantener en mente es que quizá prefieras o tambien tengas que deshabilitar los offloads en el enlace de subida del [Host de la maquina virtual](http://es.wikipedia.org/wiki/Hipervisor).

Y eso es todo. Offloading para nodos finales es gandioso, para los routers es un problema.


## Práctica

Así que, si quieres ejecutar Jool, debes de desactivar el offloading. Así es como comenzamos a hacerlo (el alcance puede variar):

{% highlight bash %}
$ sudo apt-get install ethtool
{% endhighlight %}

Luego aplica esto a toda interfáz relevante:

{% highlight bash %}
$ sudo ethtool --offload [your interface here] gro off
{% endhighlight %}

"gro" es por sus siglas en inglés "Generic Receive Offload". Actualmente no sabemos con certeza por que no tenemos que desactivar lro (Large receive offload), gso (Generic segmentation offload) y quizá otros (vea `man ethtool`). Si no estás seguro, yo diria que debes ir a lo seguro y deshacerte de todas las variantes que veas:


{% highlight bash %}
$ sudo ethtool --offload [your interface here] tso off
$ sudo ethtool --offload [your interface here] ufo off
$ sudo ethtool --offload [your interface here] gso off
$ sudo ethtool --offload [your interface here] gro off
$ sudo ethtool --offload [your interface here] lro off
{% endhighlight %}

(Si puedes iluminarnos mas en cuanto a este tema, por favor notificanos - [jool@nic.mx](mailto:jool@nic.mx).)

Algunas veces ethtool asegura que no puede cambiar algunas de las variantes, pero ten en cuenta que es usualmente por que no esta soportado y por lo tanto no estaba en un principio. Verifica tu configuración utilizando

{% highlight bash %}
$ sudo ethtool --show-offload [your interface here]
{% endhighlight %}

Suerte!
