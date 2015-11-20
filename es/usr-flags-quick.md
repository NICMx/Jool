---
language: es
layout: default
category: Documentation
title: --quick
---

[Documentación](documentation.html) > [Aplicación de Espacio de Usuario](documentation.html#aplicacin-de-espacio-de-usuario) > `--quick`

# \--quick

Partiendo de que

* La [entrada de pool4](pool4.html) _A_ es dueña del [registro BIB](bib.html) _B_ si y solo si _A_ contiene la dirección de transporte IPv4 de _B_.
* El [prefijo de pool6](usr-flags-pool6.html) _P_ es dueño de la [sessión](usr-flags-session.html) _S_ si y solo si _P_ es prefijo de la dirección IPv6 "local" de _S_.

Si se utiliza `--remove` o `--flush` en un dueño, sus "esclavos" se vuelven obsoletos porque los paquetes que las utilizan dejarán de ser traducidos.

- Si se omite `--quick` al remover, Jool se va a deshacer de los esclavos que se acaban de quedar huérfanos. Esto limpia la memoria, lo cual a su vez optimiza la búsqueda de entradas durante traducciones.
- Si se utiliza `--quick`, Jool solamente va a limpiar a los dueños. Esto puede hacerse si se desea que el borrado termine rápidamente, o más probablemente se desea volver a agregar el dueño en el futuro (en cuyo caso los esclavos que todavía sigan vivos van a volver a ser relevantes).

Los esclavos huérfanos permanecerán inactivos en la base de datos, y eventualmente se removerán automáticamente una vez que sus condiciones de expiración normales se cumplan. Por ejemplo, sesiones huérfanas van a destruirse cuando se acaben sus tiempos de vida.

