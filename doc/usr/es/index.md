---
language: es
layout: default
category: Home
title: Inicio
---

# Página Principal

-------------------

## Introducción

Jool es un [SIIT y NAT64](intro-nat64.html) de código abierto para Linux.

* Para familiarizase con el software vaya a [documentación](documentation.html).
* Para descargar Jool presione [descargas](download.html).

-------------------

## Estatus

El objetivo actual es terminar de alinear a Jool a los [requerimientos de la IETF](intro-jool.html#cumplimiento). 

La agenda al 2015-09-04 es:

1. La [Versión 4.0.0](https://github.com/NICMx/NAT64/issues?q=milestone%3A4.0.0) va a ser una [migración de framework](https://github.com/NICMx/NAT64/issues/140). Se está considerando convertir a Jool en un device driver o en un daemon, y se estima que esto permitirá el cumplir en su totalidad a los RFCs más relevantes, y que a su vez, lo hará más intuitivo de configurar.
2. La [Versión 4.1.0](https://github.com/NICMx/NAT64/issues?q=milestone%3A4.1.0) añadirá funcionalidad nueva.

Es probable que se generen versiones intermedias dependiendo de cómo evoluciona el [bug tracker](https://github.com/NICMx/NAT64/issues). La retroalimentación de los usuarios puede modificar la agenda. Para proporcionar alguna recomedación o reportar algún error vaya a [contactos](contact.html).

La versión más reciente es la [3.4.0](https://github.com/NICMx/NAT64/issues?q=milestone%3A3.4.0).

-------------------

## Noticias

### 2015-08-17

Versión 3.3.3 liberada.

[Error crítico #166 corregido](https://github.com/NICMx/NAT64/issues/166) ![heavy_exclamation_mark](../images/heavy_exclamation_mark.png)

Además en esta versión:

1. [Se añadió el soporte para el framework DKMS!](https://github.com/NICMx/NAT64/pull/165)
2. Se corrigieron los errores [#150](https://github.com/NICMx/NAT64/issues/150) y [#151](https://github.com/NICMx/NAT64/issues/151).

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

![small_red_triangle](../images/small_red_triangle.png) Sentimos el [inconveniente provocado por la certificación del sitio](https://github.com/NICMx/NAT64/issues/149). Está siendo generada, por lo que los archivos de la lista de correos no están disponibles todavía.


### 2015-03-11

[Error importante #137 descubierto](https://github.com/NICMx/NAT64/issues/137) ![heavy_exclamation_mark](../images/heavy_exclamation_mark.png)

Se libero Jool 3.3.1 para resolver dicho problema.

### 2015-03-09

Se ha concluido Jool 3.3.0.

![small_red_triangle](../images/small_red_triangle.png) [Las polítcas de Filtrado aún no son soportadas en esta versión](https://github.com/NICMx/NAT64/issues/41#issuecomment-76861510), pero la traducción Stateless (SIIT) es ahora parte del proyecto.

Los siguientes recursos están disponibles: [introducción a SIIT/NAT64](intro-nat64.html), [tutorial - SIIT](mod-run-vanilla.html) y [tutorial - SIIT/DC](mod-run-464xlat.html).

Se reorganizó el programa de configuración de Jool, por favor **actualice sus scripts**:

- El MTU ahora es elegible desde el kernel, [eliminando el uso de la bandera `--minMTU6`](mtu.html).
- `--address`, `--prefix`, `--bib4` y `--bib6` fueron omitidos por ser considerados redundantes. Ver [`--pool6`](usr-flags-pool6.html), [`--pool4`](usr-flags-pool4.html) y [`--bib`](usr-flags-bib.html).
- Otras tres banderas globales fueron omitidas por  [diferentes razones](usr-flags-atomic.html).

Además se liberó la actualización de Jool a la versión  3.2.3 para corregir [los errores encontrados](https://github.com/NICMx/NAT64/milestones/3.2.3) desde la versión 3.2.2. Se realizó una corrección importante a la vulnerabilidad DoS (denegación del servicio), por lo que actualizar es totalmente recomendable.

### 2014-10-24

El <a href="https://github.com/NICMx/NAT64/issues/112" target="_blank"> error importante #112 </a> fue descubierto, y la versión 3.2.2 queda ya desactualizada.

### 2014-10-17

La documentación a cerca de la bandera `--plateaus` ha sido [mejorada](usr-flags-plateaus.html), y su [definición](usr-flags-global.html#mtu-plateaus) también.

![small_red_triangle](../images/small_red_triangle.png) Se ha detectado que <a href="https://github.com/NICMx/NAT64/issues/111" target="_blank">falta por incluir una explicación acerca de las IP literals</a>, esto quedará dentro de la próxima actualización.

### 2014-10-08

versión 3.2.1 liberada. La serie 3.2 es considerada más madura que la 3.1.

Los cambios importantes son:

1. <a href="https://github.com/NICMx/NAT64/issues/106" target="_blank">Jool siempre intentará enmascarar los paquetes usando el primer prefijo de la pool</a>. Esto significa que Jool no era capaz de manejar más que un único prefijo.
2. La <a href="https://github.com/NICMx/NAT64/issues/109" target="_blank">pérdida de memoria en el kernel</a> ha sido corregida.

Los cambios menos relevantes son:

1. `log_martians` <a href="https://github.com/NICMx/NAT64/issues/107" target="_blank">no es incluido como un paso </a> al insertar Jool (aunque no afecta si usted lo mantiene).
2. <a href="https://github.com/NICMx/NAT64/issues/57" target="_blank"> La actualización del estado de SNMP es regresado</a>. Ver `nstat` y `netstat -s`.
3. El <a href="https://github.com/NICMx/NAT64/issues/108" target="_blank">checksum es actualizado correctamente en los paquetes de Error de ICMP truncados</a>.

NOTA: Cuando un error de ICMP es demasiado grande, no se fragmenta; se trunca. Esto se debe a que, puesto que es un mensaje de error entonces no es necesario que todo el mensaje llegue.

### 2014-09-01

El planeado para la realización de las pruebas fue más largo de lo esperado, pero finalmente la versión 3.2.0 está liberada.

Note que se cambio el número de versión menor, porque el programa para la configuración del Jool es ligeramente diferente. Los parámetros de configuración de un sólo valor han sido juntados en la opción de [`--general`](usr-flags-global.html) y ésta remplaza a `--filtering`, `--translate` y `--fragmentation`. La aplicación tiene además tres nuevas caracteristicas:

1. La <a href="https://github.com/NICMx/NAT64/pull/97" target="_blank">capacidad de limpiar las pools</a>.
2. Se añadió la opción de [`--quick`](usr-flags-quick.html).
3. Se añadió la opción de `--svg`, en [BIB](usr-flags-bib.html#csv) y [session](usr-flags-session.html#csv).

El segundo cambio más importante es el <a href="https://github.com/NICMx/NAT64/issues/58" target="_blank">Soportar varias conexiones de TCP simultáneas</a>. La atención a este tipo de eventos es ahora menos complicada.

Una <a href="https://github.com/NICMx/NAT64/issues/103" target="_blank">pequeña confusión</a> saco a luz que el path a la libnl <a href="https://github.com/NICMx/NAT64/commit/6455ffd898bae996ce3cab37b2fb6a3459ae096b" target="_blank">había sido codificada en el script de configuración</a>. Si usted ha tenido problemas para compilar el  programa de configuración de Jool, entonces pruebe esta nueva versión.

Lo menos relevante incluye un <a href="https://github.com/NICMx/NAT64/issues/100" target="_blank">complemento al viejo caso #65</a>, más <a href="https://github.com/NICMx/NAT64/issues/56" target="_blank">documentación del código</a> ![smiley](../images/smiley.png). La documentación para los usuarios se ha actualizado significativamente, para ver los cambios vaya <a href="https://github.com/NICMx/NAT64/commit/752ed2584534e6bf6bd481d7f4d4ababb6424efe" target="_blank">aquí</a>.

![small_red_triangle](../images/small_red_triangle.png) No se completaron los cambios para la nueva implementación del <a href="https://github.com/NICMx/NAT64/issues/104" target="_blank">mecanismo de fragmentación</a>. Esto fue uno de los principales motivos para el retrazo de esta versión. Al parecer se requiere conciliar el desfragmentador del kernel y el RFC para poder implementar las políticas de filtrado. Este sigue siendo un caso activo.

También se liberó el 3.1.6, el cual contiene pequeñas correciones al 3.1.5. Esto se hizo en consideración a los usuarios que por alguna razón requerian continuar usando la serie 3.1.x.

### 2014-06-26

Si está familiarizado con los <a href="https://help.github.com/articles/github-flavored-markdown" target="_blank">Markdown</a> y los Github's diffs, puedes encontrar los cambios en la documentación de la versión 3.1.5 <a href="https://github.com/NICMx/NAT64/commit/5295b05cf2c380055c3356d48ef56b74c0b828bb" target="_blank">aquí</a>, <a href="https://github.com/NICMx/NAT64/commit/2732f520b6616955fb81db778eab9da0f1db210c" target="_blank">aquí</a> y <a href="https://github.com/NICMx/NAT64/commit/54fc02dd5f5a22c44ac2d6be092306c34abd30ee" target="_blank">aquí</a>.

### 2014-06-18

La versión 3.1.5 fue liberada.

La más importante corrección fue al <a href="https://github.com/NICMx/NAT64/issues/92" target="_blank">caso #92</a>. Errores incorrectos de ICMP confunden a los nodos de IPv4, lo cual baja la confibilidad en el tráfico de 4-a-6.

Aparte de esto, el  programa de Configuración de Jool ha sido ajustada para que no se inhiba más cuando <a href="https://github.com/NICMx/NAT64/issues/88" target="_blank">las tablas de sesiones y BIB son grandes</a>, y <a href="https://github.com/NICMx/NAT64/issues/65" target="_blank"> para dar de baja las sesiones cuando las BIBs son borradas</a>.

Entonces, se tuvieron un par de problemas de <a href="https://github.com/NICMx/NAT64/issues/60" target="_blank">performance y optimización</a>. Colateralmente, para alinear la prioridad de debugeo versus el resto del kernel, se puso mayor cuidado de que información será registrada en el Log del Sistema para mantenerlo lo más limpio posible.

Si le interesa cuidar el performance, lea <a href="https://github.com/NICMx/NAT64/issues/91" target="_blank">este artículo</a> y la [documentación de `--minMTU6`](mtu.html). Este parámetro de configuración le ayudará a evitar la fragmentación.

Si nadie encuentra algún error crítico en esta versión, esta actualización será la última de la serie 3.1.x. Se estará trabajando para cumplir al 100% el RFC en la próxima actualización.

### 2014-04-25

La versión 3.1.4 ha sido liberada, y corrige:

1. Dos problemas de inhibición del equipo <a href="https://github.com/NICMx/NAT64/issues/90" target="_blank">caso#90</a> y <a href="https://github.com/NICMx/NAT64/issues/84" target="_blank">caso#84</a>.
2. El  programa de configuración del Jool ahora <a href="https://github.com/NICMx/NAT64/issues/86" target="_blank">resuelve nombres</a>.
3. <a href="https://github.com/NICMx/NAT64/issues/87" target="_blank">Se añade el soporte</a> para Linux 3.13+.

![x](../images/x.png) <a href="https://github.com/NICMx/NAT64/issues/90" target="_blank">No recomendamos el uso de Jool en el kernel 3.12</a>.

### 2014-03-26

La versión 3.1.3 ha sido liberada, y corrige:

1. El uso de una <a href="https://github.com/NICMx/NAT64/issues/81" target="_blank">incorrecta validación</a> no permite la configuración de Jool en ciertos sistemas.
2. Un <a href="https://github.com/NICMx/NAT64/issues/79" target="_blank">error</a> que provoca que Jool no envíe ciertos errores de ICMP.
3. Una <a href="https://github.com/NICMx/NAT64/issues/83" target="_blank">pérdida de memoria</a> en un caso de paquetes fragmentados.
4. Se realizó una ligera optimización en el algoritmo de traducción del paquete al <a href="https://github.com/NICMx/NAT64/issues/69" target="_blank">replazar algunos spinlocks con RCUs</a>.

### 2014-03-04

![bell](../images/bell.png) El Website ha sido liberado. *!Este website!*

Además se incluye un nueva actualización, Jool 3.1.2 que:

1. <a href="https://github.com/NICMx/NAT64/issues/76" target="_blank">Estándariza el procedimiento de compilación e instalación en el programa configurador de Jool</a>.
2. <a href="https://github.com/NICMx/NAT64/issues/77" target="_blank">Hace más explicto el manejo de sufijos de prefijos</a>.
3. <a href="https://github.com/NICMx/NAT64/issues/78" target="_blank">No se inhibe cuando el comando modprobe recibe argumentos inválidos </a>.

### 2014-02-21

La versión 3.1.1 ha sido liberada.

Esta contiene dos correcciones:

1. <a href="https://github.com/NICMx/NAT64/issues/75" target="_blank">Se añadió el solicitar permisos de administrador para efectuar los cambios a parámetros en el  programa de configuración del Jool.</a>
2. <a href="https://github.com/NICMx/NAT64/issues/72" target="_blank">Se corrigieron problemas de compatibilidad en los kernels ~3.1 .</a>

### 2014-01-15

![small_orange_diamond](../images/small_orange_diamond.png) La versión 3.1.0 ha sido liberada. ¡Jool, finalmente, maneja fragmentación!

Otras correcciones importantes:

* Se realizaron optimizaciones relevantes en ambas base de datos: BIB y session. El módulo deberá escalar mucho más elegantemente cuando los clientes se encuentren demandando más tráfico.
* Jool ya no requiere de otra dirección IPv4 por separado.
* El pánico del kernel cuando se removia el módulo ha sido suprimido.
* [Y además](https://github.com/NICMx/NAT64/issues?milestone=11&state=closed).

