---
language: es
layout: default
category: Documentation
title: Introducción a Jool
---

[Documentación](documentation.html) > [Introducción](documentation.html#introduccion) > Jool

# Introducción a Jool

## Índice

1. [Descripción](#descripcion)
2. [Cumplimiento](#cumplimiento)
3. [Compatibilidad](#compatibilidad)

## Descripción

Jool es una implementación de varios mecanismos de transición en IPv6. Todos en la categoría de traducción: [Stateful NAT64, SIIT y SIIT con EAM.] (intro-nat64.html) Jool es una aplicación de código abierto (open source) en Linux, desarrollado sobre Ubuntu, y probado en otros Linux (Debian, CentOS, Raspbian, RedHat, SuSE).

De Jool 1.0 a Jool 3.2.3 ->  Stateful NAT64<br /> 
De Jool 3.3.0 en delante ->  Stateful NAT64, SIIT y SIIT con EAM

##Cumplimiento

Este es el estatus actual de cumplimiento de Jool 3.3:

| RFC/borrador | Nombre de recordatorio  | Estatus |
|-----------|---------|--------|
| [RFC 6052](https://tools.ietf.org/html/rfc6052) | Traducción de dirección IP | Cumple Totalmente. |
| [RFC 6144](https://tools.ietf.org/html/rfc6144) | Marco de traducción IPv4/IPv6 | Cumple Totalmente. |
| [RFC 6145](https://tools.ietf.org/html/rfc6145) | SIIT | Cumple Totalmente. [Esta en desuso el empleo de los fragmentos atómicos](usr-flags-atomic.html#overview). . |
| [RFC 6146](https://tools.ietf.org/html/rfc6146) | Stateful NAT64 | Por Completar.<br />(Problemas por la implementación del RFC 6145)<br />[(Políticas de Filtrado)](https://github.com/NICMx/NAT64/issues/41). |
| [RFC 6384](http://tools.ietf.org/html/rfc6384) | FTP sobre NAT64 | [Por Completar](https://github.com/NICMx/NAT64/issues/114). |
| [RFC 6791](https://tools.ietf.org/html/rfc6791) | Peculiaridades de ICMP | Por Implementar.<br /> (Unificar Pool de direcciones en IPv4)<br /> (Extensión del encabezado de ICMP) |
| [RFC 6877](http://tools.ietf.org/html/rfc6877) | 464XLAT | Implementado como SIIT-DC; vea abajo. |
| [draft-ietf-v6ops-siit-dc]({{ site.draft-siit-dc }}) | SIIT-DC | Cumple Totalmente. |
| [draft-ietf-v6ops-siit-dc-2xlat]({{ site.draft-siit-dc-2xlat }}) | SIIT-DC Edge Translator | [Modo basado en Host.]({{ site.draft-siit-dc-2xlat }}#section-3.1) No Implementado. |
| [draft-ietf-6man-deprecate-atomfrag-generation]({{ site.draft-deprecate-atomfrag-generation }}) | Deprecación de los Fragmentos Atómicos | Los continuamos soportando, pero [no recomendamos su uso](usr-flags-atomic.html#overview). |
| [draft-anderson-v6ops-siit-eam]({{ site.draft-siit-eam }}) | EAM | Cumple totalmente. |

:email: Por favor, [haznos saber](https://github.com/NICMx/NAT64/issues) si encuentras problemas de cumplimiento adicionales o RFCs/drafts que no hayamos considerado.

## Compatibilidad

 Soportamos los kernels de Linux del 3.0 en adelante para Jool 3.1.x y 3.2.x
 
 Soportamos los kernels de Linux del 3.2 en adelante para Jool 3.3.x
 
 El desarrollo se ha hecho usando las distribuciones LTS de Ubuntu 12.04 y 14.04, pero hemos realizado una saludable cantidad de pruebas formales en Jool 3.1.5, 3.1.6, 3.2.0, 3.2.1, 3.2.2 y 3.3.2 en las siguientes variantes:

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

:small_red_triangle_down: Red Hat y CentOS muestran un warning debido a un error entre el kernel de base usado en Red Hat y el de Debian. <a href="https://github.com/NICMx/NAT64/issues/105" target="_blank">Estamos buscando aún cómo eliminarlo</a>, pero este mensaje no es crítico porque no nos ha ocasionado problemas durante las pruebas.
