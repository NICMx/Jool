---
language: es
layout: default
category: Documentation
title: Logging
---

# Logging

Si Jool tiene algo que decir, lo hará en las bitácoras del kernel (al igual que cualquier otro componente del kernel). Típicamente, estas se pueden consultar de las siguientes maneras:

- Corriendo `dmesg`.
- Leyendo el archivo `/var/log/syslog`.
- En la consola, [siempre y cuando esté escuchando mensajes del kernel](http://unix.stackexchange.com/a/13023).

Afortunadamente, Linux es generalmente callado después de iniciar, de modo que los últimos mensajes de Jool deberían encontrarse al final.

Jool usa cuatro niveles en el espectro de severidad (ver `dmesg --help`):

1. err: "La petición no se puede atender, usuario". Esto solo sucede al insertar o remover el módulo, y como respuesta a comandos de la aplicación de usuario.
2. warn: "Cuidado; voy a seguir haciendo esto, pero la configuración es sospechosa". Solamente sucede durante traducciones de paquetes.
3. info: "El módulo fue insertado", "el módulo fue removido". También los mensajes impresos por [`--logging-bib`](usr-flags-global.html#logging-bib) y [`--logging-session`](usr-flags-global.html#logging-session).
4. debug: "Y ahora estoy haciendo esto". "No pude traducir el paquete porque X, y creo que es normal".

Los mensajes debug son normalmente excluidos de los binarios de Jool durante compilación porque son demasiados y pueden alentar la operación. Sin embargo, cuando la causa de algún problema no está clara, pueden ser de ayuda.

Si se desea que Jool imprima mensajes de debug, es necesario volver al paso de la compilación e incluir la bandera `-DDEBUG`. Después de reinstalar y reinsertar normalmente, Jool debería imprimir mensajes al ver tráfico, que deberían ser de ayuda al buscar problemas con la configuración:

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

Estos mensajes rápidamente se acumulan. Si la máquina guarda estas bitácoras, es recomendable revertir los binarios una vez el problema está encontrado y resuelto.

Si `dmesg` se niega a imprimir los mensajes, puede ser necesario modificar su `--console-level`. Ver `man dmesg` para encontrar detalles.

