---
language: es
layout: default
category: Documentation
title: Logging
---

# Logging

Si Jool tiene algo que decir, lo hará en las bitácoras del kernel, al igual que cualquier otro componente del kernel. Por lo general, estos registros se pueden consultar de las siguientes maneras:

- Corriendo `dmesg`.
- Leyendo el archivo `/var/log/syslog`.
- Siendo desplegadas automáticamente en la consola, [siempre y cuando se esté escuchando los mensajes del kernel](http://unix.stackexchange.com/a/13023).

Afortunadamente, Linux generalmente apaga esta funcionalidad después de terminar de iniciar el sistema, de modo que los mensajes de Jool serán incluidos al final.

Jool usa cuatro niveles de prioridades en el espectro de severidad, versus ocho que maneja dmesg, vea `dmesg --help`. En otras palabras, Jool reporta cuatro tipos de mensajes:

1. err:   `De error`, como: "La petición de configuración no se pudo efectuar". Esto puede suceder al insertar o remover el módulo, y como respuesta a comandos de la aplicación de usuario.
2. warn:  `De aviso preventivo`, como: "Cuidado, voy a hacerlo, pero la configuración es sospechosa". Solamente sucede durante la traducciones de paquetes.
3. info:  `De aviso informativo`, como: "El módulo fue insertado", "el módulo fue removido". Además, también los mensajes impresos por [`--logging-bib`](usr-flags-global.html#logging-bib) y [`--logging-session`](usr-flags-global.html#logging-session).
4. debug: `De rastreo de errores`, como: "Estoy haciendo esto". "No se pudo traducir el paquete porque ...".

Los mensajes de rastreo son normalmente excluidos de los binarios de Jool durante compilación porque podrían ser demasiados y alentarían la operación. Sin embargo, cuando la causa de algún problema no es clara, serán de gran ayuda. Para hacer esto, es necesario volver al paso de la compilación e incluir la bandera `-DDEBUG`. Después de reinstalar y reinsertar, Jool imprimirá mensajes relacionados con el tráfico, que servirán de marco de referencia para encontrar problemas de configuración, de inhibición, de panic, etc.

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

Dado que estos mensajes se acumulan rápidamente, es muy recomendable deshabilitar la opción de rastreo generando nuevamente los binarios una vez que el problema sea encontrado y resuelto.

> **Nota:**
>
> Si `dmesg` se niega a imprimir los mensajes, puede ser necesario modificar su `--console-level`. 
> Vea `man dmesg` para encontrar detalles.

