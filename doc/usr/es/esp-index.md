---
layout: index
title: Jool - Home
---

# Página Principal

-------------------

## Introducción

Jool es un [SIIT y NAT64](intro-nat64.html) para Linux.

* [Haz click aquí](esp-doc-index.html) para empezar a familiarizarte con el software.
* [Haz click aquí](esp-download.html) para descargar Jool.

-------------------

## Estatus

Nuestra meta actual es que Jool sea un SIIT y un Stateful NAT64 [apegado a los estándares de la IEEE](intro-jool.html#cumplimiento). Nuestro agenda al 2015-04-13 es:

1. La [Versión 3.4.0](https://github.com/NICMx/NAT64/issues?q=milestone%3A3.4.0) será una refactorización para [remover de Jool  Stateful NAT64 la necesidad de una segunda dirección IPv4](https://github.com/NICMx/NAT64/wiki/issue67:-Linux%27s-MASQUERADING-does-not-care-about-the-source-natting-overriding-existing-connections.), y [optimizar el pool4](https://github.com/NICMx/NAT64/issues/36). (De hecho, son practicamente el mismo bug.)


2. La [Versión 4.0.0](https://github.com/NICMx/NAT64/issues?q=milestone%3A4.0.0) implicará una [una reprogramación completa ](https://github.com/NICMx/NAT64/issues/140). Se está evaluando las alternativas de programarlo como un pseudo device o servicio (daemon) en el userspace. Se estima que esto lo hará más protable y simple de configurar, pero con algo de demérito en su performance.

3. La [Versión 4.1.0](https://github.com/NICMx/NAT64/issues?q=milestone%3A4.1.0) añadirá muchas caracteristicas nuevas.


Es posible que existan versiones intermedias dependiendo de los problemas reportados. Sus sugerencias puede persuadirnos para cambiar prioridades. Si tienes alguna recomedación que darnos, presiona [aquí](esp-contact.html).

Nuestra versión mas reciente es la [3.3.2](https://github.com/NICMx/NAT64/issues?q=milestone%3A3.3.2).

-------------------

## Noticias

### 2015-04-14

Versión 3.3.2 liberada.

Este es el resumen:

- Hay tres nuevos parámetros de configuración:
	- [`--source-icmpv6-errors-better`](esp-usr-flags-global.html#source-icmpv6-errors-better)
	- [`--logging-bib`](esp-usr-flags-global.html#logging-bib) y [`--logging-session`](esp-usr-flags-global.html#logging-session)
- Correcciones a la Herramienta de Configuración de Jool.

Se dieron de alta dos listas de correo:

- jool-news@nic.mx para emitir noticias. Exclusivo para anunciar las nuevas liberaciones. Ház [click aquí](https://mail-lists.nic.mx/listas/listinfo/jool-news) para empezar a recibirlas.
- jool-list@nic.mx para discusión pública (ayuda, propuestas, etc.) y noticias. Haz [click aquí](https://mail-lists.nic.mx/listas/listinfo/jool-list) para registrarte.

[jool@nic.mx](mailto:jool@nic.mx) aun puede ser utilizado para accesar a los desrrolladores.

También nos gustaria disculparnos por el [inconveniente que tuvimos recientemente con el certificado](https://github.com/NICMx/NAT64/issues/149). Aunque estan siendo generados, los archivos de la lista de correos no estan disponibles todavia, y esto está en la lista de pendientes de nuestros administradores.


### 2015-03-11

[Error importante ](https://github.com/NICMx/NAT64/issues/137) descubierto!

Precisamente, ya liberamos Jool 3.3.1 para resolver éste.

### 2015-03-09

Se ha concluido Jool 3.3.0.

[Las polítcas de Filtrado aún no son soportadas en esta versión](https://github.com/NICMx/NAT64/issues/41#issuecomment-76861510), pero las traducciones tipo Stateless IP/ICMP (SIIT) son ahora soportadas.

Lee la [introducción a SIIT/NAT64](intro-nat64.html) para conocer este nuevo paradigma. [Aqui encontras el tutorial](mod-run-vanilla.html). Para una mejor comprensión, lee sobre [464XLAT](mod-run-464xlat.html).

Se reorganizó la herramienta de configuración de Jool, por favor actualiza tus scripts:

- El MTU es seleccionado desde el kernel [replazando a `--minMTU6`](misc-mtu.html).
- `--address`, `--prefix`, `--bib4` y `--bib6` fueron omitidos por ser considerados redundantes. Ver [`--pool6`](usr-flags-pool6.html), [`--pool4`](usr-flags-pool4.html) y [`--bib`](usr-flags-bib.html).
- Tres banderas globales fueron omitidas por  [diferentes razones](usr-flags-atomic.html).

También se liberó la actualización de Jool 3.2.3, para corregir [los errores encontrados](https://github.com/NICMx/NAT64/milestones/3.2.3) desde la versión 3.2.2. Uno de los principales errores es sobre la vulnerabilidad de DoS. Actualizar es altamente recomendada.

### 2014-10-24

Un <a href="https://github.com/NICMx/NAT64/issues/112" target="_blank"> error importante</a> fue descubierto, y la version 3.2.2 tiene problemas.

### 2014-10-17

La documentación provista sobre `--plateaus` ha sido [mejorada](usr-flags-plateaus.html). Su [definición](usr-flags-global.html#mtu-plateaus) también ha sido mejorada.

Ha llamado nuestra atención que <a href="https://github.com/NICMx/NAT64/issues/111" target="_blank">nosotros tampoco hemos incluido una explicación acerca de las IP literals</a>, esto quedará dentro de la próxima actualización.

### 2014-10-08

Version 3.2.1 liberada. La serie 3.2 es ahora considerada mas madura que la 3.1.

Los cambios importantes son

1. <a href="https://github.com/NICMx/NAT64/issues/106" target="_blank">Jool siempre intentará enmascarar los paquetes usando el primer prefijo de la pool</a>. Esto significa que Jool no es capaz de manejar mas que un solo prefijo.
2. La <a href="https://github.com/NICMx/NAT64/issues/109" target="_blank">pérdida de memoria en el kernel</a> ha sido corregida.

Los cambios menos relevantes son

1. `log_martians` <a href="https://github.com/NICMx/NAT64/issues/107" target="_blank">no es incluido como un paso </a> al insertar Jool (aunque no afecta si usted lo mantiene).
2. <a href="https://github.com/NICMx/NAT64/issues/57" target="_blank"> La actualización del estado de SNMP es regresado</a>. Ver `nstat` y `netstat -s`.
3. En los paquetes Corner-case el <a href="https://github.com/NICMx/NAT64/issues/108" target="_blank">checksum es actualizado correctamente</a>.

### 2014-09-01

It took it a really long time to overcome testing, but version 3.2.0 is finally released.

We changed the minor version number this time, because the userspace application has a slightly different interface; the single-value configuration parameters have been joined: [`--general`](usr-flags-global.html) replaced `--filtering`, `--translate` and `--fragmentation`. The application also has three new features:

1. The <a href="https://github.com/NICMx/NAT64/pull/97" target="_blank">ability to flush the pools</a>.
2. The addition of [`--quick`](usr-flags-quick.html).
3. The addition of `--svg`, in [BIB](usr-flags-bib.html#csv) and [session](usr-flags-session.html#csv).

The second main novelty is the finally correct implementation of <a href="https://github.com/NICMx/NAT64/issues/58" target="_blank">Simultaneous Open of TCP Connections</a>. The translation pipeline should now be completely quirkless.

A <a href="https://github.com/NICMx/NAT64/issues/103" target="_blank">little confusion</a> also revealed that the path to libnl <a href="https://github.com/NICMx/NAT64/commit/6455ffd898bae996ce3cab37b2fb6a3459ae096b" target="_blank">used to be hardcoded in the configuration script</a>. If you used to have trouble compiling the userspace application, you might want to try again using the new version.

The more unnoticeable stuff includes a <a href="https://github.com/NICMx/NAT64/issues/100" target="_blank">complement to the old issue #65</a> and a <a href="https://github.com/NICMx/NAT64/issues/56" target="_blank">healthier code-to-comment ratio</a> :). The user documentation, on the other hand, received a significant refactor, so looking at the <a href="https://github.com/NICMx/NAT64/commit/752ed2584534e6bf6bd481d7f4d4ababb6424efe" target="_blank">diff</a> might not be overly productive this time.

One thing we did not complete was the <a href="https://github.com/NICMx/NAT64/issues/104" target="_blank">fragmentation refactor</a>. This is in fact the reason why this milestone dragged. We appear to really need to reconcile the kernel's defragmenter and the RFC in order to implement filtering policies however, so it's still considered an active issue.

We also released 3.1.6, which is small fixes from 3.1.5, in case somebody has a reason to continue using the 3.1.x series.

### 2014-06-26

By the way:

If you can read <a href="https://help.github.com/articles/github-flavored-markdown" target="_blank">Markdown</a> and Github's diffs, you can find the documentation changes for version 3.1.5 <a href="https://github.com/NICMx/NAT64/commit/5295b05cf2c380055c3356d48ef56b74c0b828bb" target="_blank">here</a>, <a href="https://github.com/NICMx/NAT64/commit/2732f520b6616955fb81db778eab9da0f1db210c" target="_blank">here</a> and <a href="https://github.com/NICMx/NAT64/commit/54fc02dd5f5a22c44ac2d6be092306c34abd30ee" target="_blank">here</a>.

### 2014-06-18

Version 3.1.5 released.

Our most important fix is <a href="https://github.com/NICMx/NAT64/issues/92" target="__blank">issue #92</a>. Incorrect ICMP errors used to confuse IPv4 nodes, which lowered the reliability of 4-to-6 traffic.

Aside from that, the userspace application has been tightened. It doesn't crash silly anymore when it has to <a href="https://github.com/NICMx/NAT64/issues/88" target="__blank">output large BIB or session tables</a>, and <a href="https://github.com/NICMx/NAT64/issues/65" target="__blank">works a lot harder to keep the database free from trashy leftover records</a>.

Then we have a couple of <a href="https://github.com/NICMx/NAT64/issues/60" target="__blank">performance</a> <a href="https://github.com/NICMx/NAT64/issues/60" target="__blank">optimizations</a>. In particular (and more or less as a side effect), by aligning log priorities to those from the rest of the kernel, more care has been taken to keep the log cleaner.

If you care about performance, you might want to read the <a href="https://github.com/NICMx/NAT64/issues/91" target="__blank">as-of-now</a>-missing [documentation of `--minMTU6`](misc-mtu.html), a configuration parameter that helps you avoid fragmentation.

If people doesn't find critical bugs in this version, this appears to be the end of the 3.1.x series. We'll go back to aim for 100% RFC compliance in the next update.

### 2014-04-25

Version 3.1.4 released. Fixes:

1. Two <a href="https://github.com/NICMx/NAT64/issues/90" target="_blank">kernel</a> <a href="https://github.com/NICMx/NAT64/issues/84" target="_blank">crashes</a>.
2. The userspace application now <a href="https://github.com/NICMx/NAT64/issues/86" target="_blank">resolves names</a>.
3. <a href="https://github.com/NICMx/NAT64/issues/87" target="_blank">Added support</a> for Linux 3.13+.

Also, we <a href="https://github.com/NICMx/NAT64/issues/90" target="_blank">no longer recommend usage of Jool in kernel 3.12</a>.

### 2014-03-26

Version 3.1.3 released. Fixes:

1. An <a href="https://github.com/NICMx/NAT64/issues/81" target="_blank">incorrect implementation</a> used to ban configuration on certain systems.
2. A <a href="https://github.com/NICMx/NAT64/issues/79" target="_blank">bug</a> used to prevent Jool from sending certain ICMP errors.
3. A <a href="https://github.com/NICMx/NAT64/issues/83" target="_blank">memory leak</a>.
4. Slightly optimized the packet translation algorithm by <a href="https://github.com/NICMx/NAT64/issues/69" target="_blank">replacing some spinlocks with RCUs</a>.

### 2014-03-04

Website released. *This website!*

And with it comes a new release. 3.1.2 fixes:

1. <a href="https://github.com/NICMx/NAT64/issues/76" target="_blank">21-centuried the userspace-app's installation procedure</a>.
2. <a href="https://github.com/NICMx/NAT64/issues/77" target="_blank">Jool is now more explicit regarding the suffix of prefixes</a>.
3. <a href="https://github.com/NICMx/NAT64/issues/78" target="_blank">Jool no longer wrecks itself when modprobed with invalid arguments</a>.

### 2014-02-21

Version 3.1.1 released.

It contains two bugfixes:

1. <a href="https://github.com/NICMx/NAT64/issues/75" target="_blank">Added permission checking to the admin-related userspace requests.</a>
2. <a href="https://github.com/NICMx/NAT64/issues/72" target="_blank">Fixed compatibility issues with ~3.1 kernels.</a>

### 2014-01-15

Version 3.1.0 released. Jool finally handles fragments!

Otras correcciones importantes:

* Importantes optimizaciones en ambas la base de datos BIB y la de sessiones. El módulo deberá de escalar mucho más elegantemente cuando los clientes se encuentren demandando mas tráfico.

* Jool no requiere más una dirección IPv4 por separado.
* El pánico del kernel cuando se removia el módulo ha sido arreglado.
* Y [más cosas]https://github.com/NICMx/NAT64/issues?milestone=11&state=closed).

