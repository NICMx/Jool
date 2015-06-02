---
layout: documentation
title: Documentación - Parámetros > Quick
---

[Documentación](esp-doc-index.html) > [Herramienta de configuración de Jool](esp-doc-index.html#aplicacion-de-espacio-de-usuario) > [Parámetros](esp-usr-flags.html) > \--quick

# \--quick

Terminología:

	Partiendo que

	* La [dirección _A_ de IPv4](esp-usr-flags-pool4.html) es dueño de un [registro BIB _B_](esp-usr-flags-bib.html)  si y solo si _A_ es igual a la dirección  de IPv4 de _B_.

	* El [prefijo _P_ de IPv6](esp-usr-flags-pool6.html) es dueño de un [registro de sessión _S_](esp-usr-flags-session.html)  si y solo si _P_ corresponde a la dirección IPv6 local de S.

	Entonces cuando Jool está activo y configurado tenemos una serie de direcciones _A's_ asociados a BIBs _B's_ && prefijos _P's_ asociados a sesiones _S's_. Los procesos que se establecen mediante las entradas de las BIBs y sesiones vinen a ser "esclavos" de los primeros.


Si utilizas `--remove` o `--flush` en un dueño, es decir, en una dirección de IPv4 o Prejifo de IPv6, sus "esclavos" se volverán obsoletos por que los paquetes ya no serán traducidos, y mientras se remueve a los dueños, Jool se deshará de los nuevos esclavos huerfanos.

El borrar los dueños con sus escalvos, nos permite ahorrar memoria y nos ayuda a mantener eficiente la búsqueda de registros durante la traducción de paquetes.


** Mediante la opción de `--quick`, Jool solo purgará a los dueños. 

Los esclavos huerfanos permanecerán inactivos en la base de datos, y eventualmente se removerán a si mismos una vez que las condiciones se cumplan. Por ejemplo: las sesiones huerfanas morirán una vez que su tiempo de inactivdad permitido expire.

Esta opción es recomendable si existen muchos esclavos y se requiere limpiar las tablas lo más rápido posible o si es necesario desconfigurarlo temporalmente, en cuyo caso, al reconfigurar, los esclavos que todavia permanezcan se convertiran  en relevantes y usables de nuevo.

