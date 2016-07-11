---
language: es
layout: default
category: Home
title: Inicio
---

# Página Principal

-------------------

## Introducción

Jool es un [SIIT y NAT64](intro-xlat.html) de código abierto para Linux.

* [Aquí](documentation.html) hay documentación.
* [Aquí](download.html) está la página de descargas.

-------------------

## Estatus

Jool es un SIIT y NAT64 [razonablemente apegado a estándares](intro-jool.html#cumplimiento). Esta es la agenda hasta el 2016-07-11:

1. [La versión 3.5.0]({{ site.repository-url }}/issues?q=milestone%3A3.5.0) añadirá funcionalidad nueva.
2. [La versión 4.0.0]({{ site.repository-url }}/issues?q=milestone%3A4.0.0) va a ser una [refactorización interna]({{ site.repository-url }}/issues/140) que hará la configuración más versátil.
3. [La versión 4.1.0]({{ site.repository-url }}/issues?q=milestone%3A4.1.0) añadirá funcionalidad nueva.

A veces interpolamos versiones intermedias dependiendo de cómo evoluciona el [bug tracker]({{ site.repository-url }}/issues).

La versión más reciente es la [3.4.4]({{ site.repository-url }}/milestone/34).

-------------------

## Noticias

### 2016-07-11

Liberado Jool 3.4.4. Se corrigió un error:

1. La implementación de pool4 ([en modo vacío](usr-flags-pool4.html#notas)) solía confundir direcciones de interfaces punto-a-punto, [lo cual llevaba a paquetes tirados]({{ site.repository-url }}/issues/217).

### 2016-04-21

Jool 3.4.3 fue liberado.

1. Se agregó soporte para un mayor rango de kernels. El soporte es ahora desde Linux 3.2 hasta 4.4, y también RHEL 7.0 hasta 7.2.
2. Nueva bandera de configuración para NAT64: [`--f-args`](usr-flags-global.html#f-args)
3. Nueva bandera de configuración para NAT64: [`--handle-rst-during-fin-rcv`](usr-flags-global.html#handle-rst-during-fin-rcv)

### 2015-11-20

Jool 3.4.2 fue liberado. Se corrigieron tres bugs:

1. [Apuntadores corruptos y derrames de memoria]({{ site.repository-url }}/issues/192) causados por el vaciado y deinicialización de pool6791 y blacklist.
2. `--bib --display` y `--session --display` ahora [requieren privilegios de administrador de red]({{ site.repository-url }}/issues/191) (NAT64 Jool).
3. Se limpiaron algunas [advertencias de compilación]({{ site.repository-url }}/issues/188) reportadas por versiones antiguas de gcc.

Cuidado con el #2! Puede ser necesario actualizar scripts.

### 2015-11-11

Jool 3.4.1 fue liberado. Se corrigieron tres bugs:

1. Kernel panic debido a [incorrecto manejo de namespaces]({{ site.repository-url }}/pull/185#issuecomment-155875381).
2. Corregida [compilación para kernels 4.1 en adelante]({{ site.repository-url }}/pull/185).
3. Las aplicaciones de espacio de usuario [solían regresar éxito en errores detectados por el módulo]({{ site.repository-url }}/issues/184).

### 2015-11-04

Jool 3.4.0 fue liberado. Estos son los cambios:

1. Refactorizaciones a pool4 agregan [asignación de fuente basado en marca](usr-flags-pool4.html#mark) y [rangos de puertos](usr-flags-pool4.html#ejemplos) ([lo cual a su vez remueve la necesidad de una segunda dirección de IPv4](run-nat64.html#red-de-ejemplo)), y corrige el [uso excesivo de memoria]({{ site.repository-url }}/issues/36).
2. La EAMT ahora implementa [Hairpinning]({{ site.repository-url }}/issues/162) y [entradas superpuestas]({{ site.repository-url }}/issues/160), que son nuevas adiciones al draft de EAM.
3. Mínimo soporte de namespaces, que permite [Traducción local](node-based-translation.html) y (subjetivamente) [mejor filtrado]({{ site.repository-url }}/issues/41).
4. La aplicación de espacio de usuario ahora [imprime la versión amigable de los mensajes de error]({{ site.repository-url }}/issues/169) que solían solamente arrojarse al log del kernel.
5. Se quitó la dependencia de supresión de código muerto, [que solía prevenir compilación en algunos sistemas]({{ site.repository-url }}/issues/152).
6. [Dos]({{ site.repository-url }}/issues/174) [errores]({{ site.repository-url }}/issues/173) corregidos.
7. ¡Documentación en español!
8. `--csv` ahora puede ser usado [en todos los modos de configuración]({{ site.repository-url }}/issues/164#issuecomment-126093571).

> ![Advertencia](../images/warning.svg) Si desea actualizar Jool, tenga en mente que pool4 no es completamente compatible con su versión anterior. En Jool 3.3, cualquier paquete solía ser enmascarado usando cualquier entrada de pool4 disponible. En Jool 3.4, cada entrada de pool4 solamente enmascara paquetes que contengan una marca en específico (que es cero, por defecto). Ver [`--mark`](usr-flags-pool4.html#mark) para encontrar más detalles.

### 2015-10-15

La versión 3.3.5 fue liberada. Se corrigieron tres errores:

1. El puerto cero solía poder usarse para enmascarar paquetes (NAT64 Jool).
2. Enrutamiento incorrecto cuando pool6791 estaba vacío (SIIT Jool).
3. Derramo de memoria durante `--eamt --flush` (SIIT Jool).

### 2015-09-21

La versión 3.3.4 fue liberada.

La corrección más importante (teóricamente) es un [problema que solía interferir con Path MTU Discovery]({{ site.repository-url }}/issues/170). Jool ahora también se encarga de [ignorar multicast automáticamente]({{ site.repository-url }}/issues/168) y [trabajar mejor el campo _hop limit_]({{ site.repository-url }}/issues/167) (de la cabecera de IPv6).

También se ha notado que SIIT Jool necesita [forwarding IPv4 activo en kernels 3.5 e inferiores]({{ site.repository-url }}/issues/170#issuecomment-141507174). En otras palabras, agregar

	sudo sysctl -w net.ipv4.conf.all.forwarding=1

al procedimiento de modprobe en estos casos.

### 2015-08-17

Versión 3.3.3 liberada.

![Advertencia](../images/warning.svg) [Error crítico #166 corregido!]({{ site.repository-url }}/issues/166)

Además en esta versión:

1. [Se añadió el soporte para el framework DKMS!]({{ site.repository-url }}/pull/165)
2. Se corrigieron los errores [#150]({{ site.repository-url }}/issues/150) y [#151]({{ site.repository-url }}/issues/151).

### 2015-04-14

Versión 3.3.2 liberada.

Este es el resumen:

- Se dieron de alta tres nuevos parámetros de configuración:
	- [`--source-icmpv6-errors-better`](usr-flags-global.html#source-icmpv6-errors-better)
	- [`--logging-bib`](usr-flags-global.html#logging-bib) y [`--logging-session`](usr-flags-global.html#logging-session)
- Se realizaron correcciones a programa de configuración de Jool.

Se dieron de alta dos listas de correo:

- jool-news@nic.mx para emitir noticias. Exclusivo para anunciar las nuevas liberaciones. Haga [click aquí](https://mail-lists.nic.mx/listas/listinfo/jool-news) para suscribirse.
- jool-list@nic.mx para discusión pública (ayuda, propuestas, etc.) y noticias. Haga [click aquí](https://mail-lists.nic.mx/listas/listinfo/jool-list) para registrartse.

[jool@nic.mx](mailto:jool@nic.mx) aún puede ser utilizado para accesar a los desrrolladores.

![triangle](../images/triangle.svg) Sentimos el [inconveniente provocado por la certificación del sitio]({{ site.repository-url }}/issues/149). Está siendo generada, por lo que los archivos de la lista de correos no están disponibles todavía.


### 2015-03-11

![Advertencia](../images/warning.svg) [Error importante #137 descubierto]({{ site.repository-url }}/issues/137)!

Se libero Jool 3.3.1 para resolver dicho problema.

### 2015-03-09

Se ha concluido Jool 3.3.0.

![triangle](../images/triangle.svg) [Las polítcas de Filtrado aún no son soportadas en esta versión]({{ site.repository-url }}/issues/41#issuecomment-76861510), pero la traducción Stateless (SIIT) es ahora parte del proyecto.

Los siguientes recursos están disponibles: [introducción a SIIT/NAT64](intro-xlat.html), [tutorial - SIIT](run-vanilla.html) y [tutorial - SIIT/DC](464xlat.html).

Se reorganizó el programa de configuración de Jool, por favor **actualice sus scripts**:

- El MTU ahora es elegible desde el kernel, [eliminando el uso de la bandera `--minMTU6`](mtu.html).
- `--address`, `--prefix`, `--bib4` y `--bib6` fueron omitidos por ser considerados redundantes. Ver [`--pool6`](usr-flags-pool6.html), [`--pool4`](usr-flags-pool4.html) y [`--bib`](usr-flags-bib.html).
- Otras tres banderas globales fueron omitidas por  [diferentes razones](usr-flags-atomic.html).

Además se liberó la actualización de Jool a la versión  3.2.3 para corregir [los errores encontrados]({{ site.repository-url }}/milestones/3.2.3) desde la versión 3.2.2. Se realizó una corrección importante a la vulnerabilidad DoS (denegación del servicio), por lo que actualizar es totalmente recomendable.

### 2014-10-24

El <a href="{{ site.repository-url }}/issues/112" target="_blank"> error importante #112 </a> fue descubierto, y la versión 3.2.2 queda ya desactualizada.

### 2014-10-17

La documentación a cerca de la bandera `--plateaus` ha sido [mejorada](usr-flags-plateaus.html), y su [definición](usr-flags-global.html#mtu-plateaus) también.

![triangle](../images/triangle.svg) Se ha detectado que <a href="{{ site.repository-url }}/issues/111" target="_blank">falta por incluir una explicación acerca de las IP literals</a>, esto quedará dentro de la próxima actualización.

### 2014-10-08

versión 3.2.1 liberada. La serie 3.2 es considerada más madura que la 3.1.

Los cambios importantes son:

1. <a href="{{ site.repository-url }}/issues/106" target="_blank">Jool siempre intentará enmascarar los paquetes usando el primer prefijo de la pool</a>. Esto significa que Jool no era capaz de manejar más que un único prefijo.
2. La <a href="{{ site.repository-url }}/issues/109" target="_blank">pérdida de memoria en el kernel</a> ha sido corregida.

Los cambios menos relevantes son:

1. `log_martians` <a href="{{ site.repository-url }}/issues/107" target="_blank">no es incluido como un paso </a> al insertar Jool (aunque no afecta si usted lo mantiene).
2. <a href="{{ site.repository-url }}/issues/57" target="_blank"> La actualización del estado de SNMP es regresado</a>. Ver `nstat` y `netstat -s`.
3. El <a href="{{ site.repository-url }}/issues/108" target="_blank">checksum es actualizado correctamente en los paquetes de Error de ICMP truncados</a>.

NOTA: Cuando un error de ICMP es demasiado grande, no se fragmenta; se trunca. Esto se debe a que, puesto que es un mensaje de error entonces no es necesario que todo el mensaje llegue.

### 2014-09-01

El planeado para la realización de las pruebas fue más largo de lo esperado, pero finalmente la versión 3.2.0 está liberada.

Note que se cambio el número de versión menor, porque el programa para la configuración del Jool es ligeramente diferente. Los parámetros de configuración de un sólo valor han sido juntados en la opción de [`--general`](usr-flags-global.html) y ésta remplaza a `--filtering`, `--translate` y `--fragmentation`. La aplicación tiene además tres nuevas caracteristicas:

1. La <a href="{{ site.repository-url }}/pull/97" target="_blank">capacidad de limpiar las pools</a>.
2. Se añadió la opción de [`--quick`](usr-flags-quick.html).
3. Se añadió la opción de `--svg`, en [BIB](usr-flags-bib.html#csv) y [session](usr-flags-session.html#csv).

El segundo cambio más importante es el <a href="{{ site.repository-url }}/issues/58" target="_blank">Soportar varias conexiones de TCP simultáneas</a>. La atención a este tipo de eventos es ahora menos complicada.

Una <a href="{{ site.repository-url }}/issues/103" target="_blank">pequeña confusión</a> saco a luz que el path a la libnl <a href="{{ site.repository-url }}/commit/6455ffd898bae996ce3cab37b2fb6a3459ae096b" target="_blank">había sido codificada en el script de configuración</a>. Si usted ha tenido problemas para compilar el  programa de configuración de Jool, entonces pruebe esta nueva versión.

Lo menos relevante incluye un <a href="{{ site.repository-url }}/issues/100" target="_blank">complemento al viejo caso #65</a>, más <a href="{{ site.repository-url }}/issues/56" target="_blank">documentación del código</a>, y documentación para usuarios. Para ver los cambios de esto último visitar <a href="{{ site.repository-url }}/commit/752ed2584534e6bf6bd481d7f4d4ababb6424efe" target="_blank">aquí</a>.

![triangle](../images/triangle.svg) No se completaron los cambios para la nueva implementación del <a href="{{ site.repository-url }}/issues/104" target="_blank">mecanismo de fragmentación</a>. Esto fue uno de los principales motivos para el retrazo de esta versión. Al parecer se requiere conciliar el desfragmentador del kernel y el RFC para poder implementar las políticas de filtrado. Este sigue siendo un caso activo.

También se liberó el 3.1.6, el cual contiene pequeñas correciones al 3.1.5. Esto se hizo en consideración a los usuarios que por alguna razón requerian continuar usando la serie 3.1.x.

### 2014-06-26

Si está familiarizado con los <a href="https://help.github.com/articles/github-flavored-markdown" target="_blank">Markdown</a> y los Github's diffs, puedes encontrar los cambios en la documentación de la versión 3.1.5 <a href="{{ site.repository-url }}/commit/5295b05cf2c380055c3356d48ef56b74c0b828bb" target="_blank">aquí</a>, <a href="{{ site.repository-url }}/commit/2732f520b6616955fb81db778eab9da0f1db210c" target="_blank">aquí</a> y <a href="{{ site.repository-url }}/commit/54fc02dd5f5a22c44ac2d6be092306c34abd30ee" target="_blank">aquí</a>.

### 2014-06-18

La versión 3.1.5 fue liberada.

La más importante corrección fue al <a href="{{ site.repository-url }}/issues/92" target="_blank">caso #92</a>. Errores incorrectos de ICMP confunden a los nodos de IPv4, lo cual baja la confibilidad en el tráfico de 4-a-6.

Aparte de esto, el  programa de Configuración de Jool ha sido ajustada para que no se inhiba más cuando <a href="{{ site.repository-url }}/issues/88" target="_blank">las tablas de sesiones y BIB son grandes</a>, y <a href="{{ site.repository-url }}/issues/65" target="_blank"> para dar de baja las sesiones cuando las BIBs son borradas</a>.

Entonces, se tuvieron un par de problemas de <a href="{{ site.repository-url }}/issues/60" target="_blank">performance y optimización</a>. Colateralmente, para alinear la prioridad de debugeo versus el resto del kernel, se puso mayor cuidado de que información será registrada en el Log del Sistema para mantenerlo lo más limpio posible.

Si le interesa cuidar el performance, lea <a href="{{ site.repository-url }}/issues/91" target="_blank">este artículo</a> y la [documentación de `--minMTU6`](mtu.html). Este parámetro de configuración le ayudará a evitar la fragmentación.

Si nadie encuentra algún error crítico en esta versión, esta actualización será la última de la serie 3.1.x. Se estará trabajando para cumplir al 100% el RFC en la próxima actualización.

### 2014-04-25

La versión 3.1.4 ha sido liberada, y corrige:

1. Dos problemas de inhibición del equipo <a href="{{ site.repository-url }}/issues/90" target="_blank">caso#90</a> y <a href="{{ site.repository-url }}/issues/84" target="_blank">caso#84</a>.
2. El  programa de configuración del Jool ahora <a href="{{ site.repository-url }}/issues/86" target="_blank">resuelve nombres</a>.
3. <a href="{{ site.repository-url }}/issues/87" target="_blank">Se añade el soporte</a> para Linux 3.13+.

![Advertencia](../images/warning.svg) <a href="{{ site.repository-url }}/issues/90" target="_blank">No recomendamos el uso de Jool en el kernel 3.12</a>.

### 2014-03-26

La versión 3.1.3 ha sido liberada, y corrige:

1. El uso de una <a href="{{ site.repository-url }}/issues/81" target="_blank">incorrecta validación</a> no permite la configuración de Jool en ciertos sistemas.
2. Un <a href="{{ site.repository-url }}/issues/79" target="_blank">error</a> que provoca que Jool no envíe ciertos errores de ICMP.
3. Una <a href="{{ site.repository-url }}/issues/83" target="_blank">pérdida de memoria</a> en un caso de paquetes fragmentados.
4. Se realizó una ligera optimización en el algoritmo de traducción del paquete al <a href="{{ site.repository-url }}/issues/69" target="_blank">replazar algunos spinlocks con RCUs</a>.

### 2014-03-04

El Website ha sido liberado. *!Este website!*

Además se incluye un nueva actualización, Jool 3.1.2 que:

1. <a href="{{ site.repository-url }}/issues/76" target="_blank">Estándariza el procedimiento de compilación e instalación en el programa configurador de Jool</a>.
2. <a href="{{ site.repository-url }}/issues/77" target="_blank">Hace más explicto el manejo de sufijos de prefijos</a>.
3. <a href="{{ site.repository-url }}/issues/78" target="_blank">No se inhibe cuando el comando modprobe recibe argumentos inválidos </a>.

### 2014-02-21

La versión 3.1.1 ha sido liberada.

Esta contiene dos correcciones:

1. <a href="{{ site.repository-url }}/issues/75" target="_blank">Se añadió el solicitar permisos de administrador para efectuar los cambios a parámetros en el  programa de configuración del Jool.</a>
2. <a href="{{ site.repository-url }}/issues/72" target="_blank">Se corrigieron problemas de compatibilidad en los kernels ~3.1 .</a>

### 2014-01-15

La versión 3.1.0 ha sido liberada. ¡Jool, finalmente, maneja fragmentación!

Otras correcciones importantes:

* Se realizaron optimizaciones relevantes en ambas base de datos: BIB y session. El módulo deberá escalar mucho más elegantemente cuando los clientes se encuentren demandando más tráfico.
* Jool ya no requiere de otra dirección IPv4 por separado.
* El pánico del kernel cuando se removia el módulo ha sido suprimido.
* [Y además]({{ site.repository-url }}/issues?milestone=11&state=closed).

