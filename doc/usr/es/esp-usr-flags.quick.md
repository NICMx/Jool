---
layout: documentation
title: Documentación - Parámetros > Quick
---

[Documentación](esp-doc-index.html) > [Herramienta de configuración de Jool](esp-doc-index.html#aplicacion-de-espacio-de-usuario) > [Parámetros](esp-usr-flags.html) > \--quick

# \--quick

Terminología:

Partiendo que

* [La dirección _A_ de IPv4](esp-usr-flags-pool4.html) es dueño de un [registro BIB _B_](esp-usr-flags-bib.html)  si y solo si se cumple que _A_ es igual a la dirección  de IPv4 de _B_.

* [El prefijo _P_ de IPv6](esp-usr-flags-pool6.html) es dueño de un [registro de sessión _S_](esp-usr-flags-session.html)  si y solo si se cumple que _P_ corresponde a la dirección IPv6 local de S.

Entonces cuando Jool está activo y configurado tenemos una serie de direcciones _A's_ asociados a BIBs _B's_ && prefijos _P's_ asociados a sesiones _S's_. <br />
Los procesos que se establecen mediante las entradas de las BIBs y sesiones vinen a ser "esclavos" de los primeros.




Si utilizas `--remove` o `--flush` en un dueño, es decir, en una dirección de IPv4 o Prejifo de IPv6, sus "esclavos" se vuelven obsoletos por que los paquetes ya no serán traducidos.



* Mientras se remueve a los dueños, Jool se deshará de los nuevos esclavos huerfanos. Esto ahorra memoria y mantiene eficiente la búsqueda de registros durante la traducción de paquetes.

* Sin embargo, mediante la opción de `--quick`, Jool solo purgará a los dueños. Los esclavos huerfanos permanecerán inactivos en la base de datos, y eventualmente se removerán a si mismos <br />
  una vez que las condiciones se cumplan. Por ejemplo: las sesiones huerfanas morirán una vez que su tiempo de inactivdad permitido expire.

La opción de `--quick` es recomendable si existen muchos esclavos y se requiere limpiar las tablas lo más rápido posible o si es necesario desconfigurarlo temporalmente,<br />
en cuyo caso, al reconfigurar, los esclavos que todavia permanezcan se convertiran  en relevantes y usables de nuevo.

