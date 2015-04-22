---
layout: documentation
title: Documentación - Parámetros > Quick
---

[Documentación](esp-doc-index.html) > [Aplicación de espacio de usuario](esp-doc-index.html#aplicacin-de-espacio-de-usuario) > [Parámetros](esp-usr-flags.html) > \--quick

# \--quick

Primero, un poco de información fundamental:

* [prefijo IPv6](esp-usr-flags-pool6.html) _P_ es dueño de un [registro de sessión](esp-usr-flags-session.html) _S_ si _P_ es igual al lado de red de la dirección IPv6 local de S.

* [dirección IPv4](esp-usr-flags-pool4.html) _A_ es dueño de un registro [registro BIB](esp-usr-flags-bib.html) _B_ si _A_ es igual a la dirección  IPv4 de _B_.

Si utilizas `--remove` o `--flush` en un dueño, sus "esclavos" se vuelven obsoletos por que los paquetes relevantes ya no serán traducidos.  

* Si omites `--quick` mientras remueves a los dueños, Jool se deshará de los nuevos esclavos huerfanos. Esto ahorra memoria y mantiene eficiente la busqueda de registros durante la traducción de paquetes.

* Por otra parte, cuando utilizas `--quick`, Jool solo purgará a los dueños. Quizá quieras hacer estp si quieres que la operación tenga éxito rápido (quizá tengas un monto grande de esclavos), o mas probablemente planeas re-añadir al dueño en un futuro (en cuyo caso los esclavos que todavia permanecen se convertiran relevantes y usables de nuevo).

Los esclavos huerfanos permanecerán inactivos en la base de datos, y eventualmente se removerán a si mismos una vez que las condiciones se cumplan (ej. sesiones huerfanas morirán una vez que su tiempo de inactivdad permitido expire).