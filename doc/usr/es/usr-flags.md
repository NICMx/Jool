---
language: es
layout: default
category: Documentation
title: Documentación - Parámetros de la Herramienta de Configuración
---

[Documentación](documentation.html) > [Parámetros de la Herramienta de Configuración](documentation.html#aplicacion-de-espacio-de-usuario) > Parámetros

# Parámetros

## Introducción

Esta recopilación de documentos explican que parámetros existen para las dos modalidades: SIIT (`jool_siit`) y NAT64 Stateful (`jool`).

NOTAS:

Si todavía no has generado los ejecutables, ve a [instrucciones de compilación e instalación](usr-install.html).<br />
** Las opciones de despliegue no requieren privilegios de administrador de red, ni que la parte server este insertada, pero todos los de configuración SÍ.** Consulta:([CAP_NET_ADMIN](http://linux.die.net/man/7/capabilities)).

## Índice

Opciones comunes:

1. [`--help`](usr-flags-help.html)
2. [`--global`](usr-flags-global.html)
	1. [Atomic Fragments](usr-flags-atomic.html)
	2. [MTU Plateaus (Example)](usr-flags-plateaus.html)
3. [`--pool6`](usr-flags-pool6.html)

Opciones exclusivas de `jool_siit`:

1. [`--eamt`](usr-flags-eamt.html)
2. [`--blacklist`](usr-flags-blacklist.html)
2. [`--pool6791`](usr-flags-pool6791.html)

Opciones exclusivas de `jool`:

4. [`--pool4`](usr-flags-pool4.html)
1. [`--bib`](usr-flags-bib.html)
2. [`--session`](usr-flags-session.html)
3. [`--quick`](usr-flags-quick.html)
