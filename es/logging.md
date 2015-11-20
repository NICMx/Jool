---
language: es
layout: default
category: Documentation
title: Logging
---

[Documentación](documentation.html) > [Misceláneos](documentation.html#miscelneos) > Logging

# Logging

Si Jool tiene algo que decir, lo hará en las bitácoras del kernel, al igual que cualquier otro componente del kernel. Por lo general, estos registros se pueden consultar de las siguientes maneras:

- Corriendo `dmesg`.
- Leyendo el archivo `/var/log/syslog`.
- Siendo desplegadas automáticamente en la consola, [siempre y cuando se esté escuchando los mensajes del kernel](http://unix.stackexchange.com/a/13023).

Afortunadamente, Linux generalmente no dice mucho después de terminar de iniciar el sistema, de modo que los mensajes de Jool serán incluidos al final.

Jool usa solamente cuatro niveles de prioridades en el espectro de severidad (vea `dmesg --help`). En otras palabras, Jool reporta cuatro tipos de mensajes:

1. err: Mensajes de error ("la petición de configuración no se pudo efectuar"). Esto puede suceder al insertar o remover el módulo, y como respuesta a comandos de la aplicación de usuario.
2. warn: Indica que Jool sospecha que algo está mal configurado. Solamente sucede durante traducciones de paquetes.
3. info: De naturaleza informativa ("El módulo fue insertado", "el módulo fue removido"). También abarca los mensajes impresos por [`--logging-bib`](usr-flags-global.html#logging-bib) y [`--logging-session`](usr-flags-global.html#logging-session).
4. debug: Se imprimen en cada paso, e indican lo que está haciendo Jool actualmente: "Estoy haciendo esto". "No se pudo traducir el paquete, y me parece que es normal".

Los mensajes de rastreo son normalmente excluidos de los binarios de Jool durante compilación porque podrían pueden ser demasiados y retardar la operación. Sin embargo, cuando la causa de algún problema no es clara, pueden de ayuda. Para ver estos mensajes, es necesario volver al paso de la compilación e incluir la bandera `-DDEBUG`. Después de reinstalar y reinsertar, Jool imprimirá mensajes relacionados con el tráfico, que servirán de marco de referencia para encontrar problemas de configuración.

	$ cd Jool/mod
	$ make JOOL_FLAGS=-DDEBUG  # -- Esta es la clave -- 
	$ sudo make modules_install
	$ sudo depmod
	$
	$ sudo modprobe -r jool_siit
	$ sudo modprobe jool_siit pool6=...
	$
	$ dmesg | tail -5
	[ 3465.639622] ===============================================
	[ 3465.639655] Catching IPv4 packet: 192.0.2.16->198.51.100.8
	[ 3465.639724] Translating the Packet.
	[ 3465.639756] Address 192.0.2.16 lacks an EAMT entry and there's no pool6 prefix.
	[ 3465.639806] Returning the packet to the kernel.

Dado que estos mensajes se acumulan rápidamente, es muy recomendable deshabilitar debug generando nuevamente los binarios una vez que el problema ha sido encontrado y resuelto.

> ![Nota](../images/bulb.svg) Si `dmesg` se niega a imprimir los mensajes, puede ser necesario modificar su `--console-level`. 
> Ver `man dmesg` para encontrar detalles.

