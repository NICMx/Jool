---
language: es
layout: default
category: Documentation
title: Documentación - Parámetros de la Herramienta de Configuración
---

[Documentación](documentation.html) > [Parámetros de la Herramienta de Configuración](documentation.html#aplicacion-de-espacio-de-usuario) > Parámetros

# Parámetros

## Introducción

Esta recopilación de documentos explica los parámetros para las aplicaciones de espacio de usuario:

1. La aplicación `jool` sirve para configurar al módulo `jool` (Stateful NAT64).
2. La aplicación `jool_siit` sirve para configurar al módulo `jool_siit` (SIIT).

Instrucciones para instalar estos binarios se pueden encontrar [aquí](usr-install.html).

![!](../images/heavy_exclamation_mark.png) Opciones que modifiquen el comportamiento del traductor requieren privilegios de administrador de red ([CAP_NET_ADMIN](http://linux.die.net/man/7/capabilities)). Opciones de consulta pueden correrse libremente.

## Índice

Opciones comunes:

1. [`--help`](usr-flags-help.html)
2. [`--global`](usr-flags-global.html)
	1. [Fragmentos atómicos](usr-flags-atomic.html)
	2. [MTU Plateaus (Ejemplo)](usr-flags-plateaus.html)
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
