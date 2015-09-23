---
language: es
layout: default
category: Documentation
title: Introducción a Jool
---

[Documentación](documentation.html) > [Introducción](documentation.html#introduccin) > Jool

# Introducción a Jool

## Índice

1. [Descripción](#descripcin)
2. [Cumplimiento](#cumplimiento)
3. [Compatibilidad](#compatibilidad)

## Descripción

Jool es una implementación de código abierto de dos mecanismos de transición a IPv6: [SIIT y Stateful NAT64](intro-nat64.html).

De Jool 1.0 a Jool 3.2.3 ->  Stateful NAT64<br /> 
De Jool 3.3.0 en delante ->  Stateful NAT64, SIIT y SIIT con EAM

##Cumplimiento

Este es el estatus actual de cumplimiento de Jool 3.3:

| RFC/borrador | Nombre de recordatorio  | Estatus |
|-----------|---------|--------|
| [RFC 6052](https://tools.ietf.org/html/rfc6052) | Traducción de dirección IP | Cumple Totalmente. |
| [RFC 6144](https://tools.ietf.org/html/rfc6144) | Marco de traducción IPv4/IPv6 | Cumple Totalmente. |
| [RFC 6145](https://tools.ietf.org/html/rfc6145) | SIIT | Cumple, pero [la implementación de fragmentos atómicos está descuidada](usr-flags-atomic.html#overview). |
| [RFC 6146](https://tools.ietf.org/html/rfc6146) | Stateful NAT64 | Falta implementar [Políticas de Filtrado](https://github.com/NICMx/NAT64/issues/41). |
| [RFC 6384](http://tools.ietf.org/html/rfc6384) | FTP sobre NAT64 | [Por Completar](https://github.com/NICMx/NAT64/issues/114). |
| [RFC 6791](https://tools.ietf.org/html/rfc6791) | Peculiaridades de ICMP | El RFC quiere dos cosas: [pool6791](usr-flags-pool6791.html) (implementado) y extensión de encabezado de ICMP (no implementado). |
| [RFC 6877](http://tools.ietf.org/html/rfc6877) | 464XLAT | Implementado como SIIT-DC; ver abajo. |
| [draft-ietf-v6ops-siit-dc]({{ site.draft-siit-dc }}) | SIIT-DC | Cumple Totalmente. |
| [draft-ietf-v6ops-siit-dc-2xlat]({{ site.draft-siit-dc-2xlat }}) | SIIT-DC Edge Translator | [Modo basado en Host]({{ site.draft-siit-dc-2xlat }}#section-3.1) No Implementado. |
| [draft-ietf-6man-deprecate-atomfrag-generation]({{ site.draft-deprecate-atomfrag-generation }}) | Deprecación de los Fragmentos Atómicos | Jool contiene código que maneja fragmentos atómicos, pero [va de salida](usr-flags-atomic.html#overview). |
| [draft-anderson-v6ops-siit-eam]({{ site.draft-siit-eam }}) | EAM | Cumple totalmente. |

![email](../images/email.png) Favor de comunicarse mediante el [Bug Tracker](https://github.com/NICMx/NAT64/issues) si encuentra algún problema de cumplimiento adicional o RFCs/drafts que no se hayan considerado.

## Compatibilidad

 Existe el soporte a los kernels de Linux del 3.0 en adelante para Jool 3.1.x y 3.2.x
 
 Existe el soporte a los kernels de Linux del 3.2 en adelante para Jool 3.3.x
 
 El desarrollo se ha hecho usando las distribuciones LTS de Ubuntu 12.04 y 14.04, y se han realizado una saludable cantidad de pruebas formales en Jool 3.1.5, 3.1.6, 3.2.0, 3.2.1, 3.2.2 y 3.3.2 en las siguientes variantes:

| Distribución | Kernels |
| -------------|---------|
| CentOS 7 | 3.10.0-123.el7.x86_64 |
| Debian 7.5 | 3.2.0-4-amd64 |
| Red Hat Enterprise Linux 7 | 3.10.0-123.4.4.el7.x86_64 |
| SuSE Linux Enterprise Desktop 11 SP3 | 3.0.101-0.31-default |
| Ubuntu 12.04 | 3.1.10-030110-generic, 3.2.60-030260-generic |
| Ubuntu 12.10 | 3.3.8-030308-generic, 3.4.94-030494-generic, 3.5.7-03050733-generic |
| Ubuntu 13.04 | 3.6.11-030611-generic, 3.7.10-030710-generic, 3.8.13-03081323-generic |
| Ubuntu 13.10 | 3.9.11-030911-generic, 3.10.44-031044-generic, 3.11.10-03111011-generic |
| Ubuntu 14.04 | 3.12.22-031222-generic, 3.13.11-03131103-generic |
| Ubuntu 14.10 | 3.14.8-031408-generic, 3.15.1-031501-generic |

![small_red_triangle_down](../images/small_red_triangle_down.png) La compilación en Red Hat y CentOS muestran warnings debido a diferencias entre el API de los kernels de Red Hat y Debian. <a href="https://github.com/NICMx/NAT64/issues/105" target="_blank">. Esto no ha causado problemas en las pruebas</a>, sin embargo se está en búsqueda de quitarlos.
