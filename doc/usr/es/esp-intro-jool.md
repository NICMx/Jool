---
layout: documentation
title: Documentación - Introducción a Jool
---

[Documentación](esp-doc-index.html) > [Introducción](esp-doc-index.html#introduccion) > Jool

# Introducción a Jool

## Indice

1. [Descripción](#descripcion)
2. [Cumplimiento](#cumplimiento)
3. [Compatibilidad](#compatibilidad)

## Descripción

Jool es una implementación de código abierto(Open Source) de [Traducción IPv4/IPv6](esp-intro-nat64.html) en Linux. Hasta la versión  3.2.x, solía ser sólo un Stateful NAT64; a partir de la versión 3.3.0, también soporta el modo SIIT.

##Cumplimiento

Este es el estatus actual de cumplimiento de Jool 3.3:

| RFC/borrador | Nombre de recordatorio  | Estatus |
|-----------|---------|--------|
| [RFC 6052](https://tools.ietf.org/html/rfc6052) | Traducción de dirección IP | Cumple Totalmente. |
| [RFC 6144](https://tools.ietf.org/html/rfc6144) | Marco de traducción IPv4/IPv6 | Cumple Totalmente. |
| [RFC 6145](https://tools.ietf.org/html/rfc6145) | SIIT | La implementación de fragmentos atómicos [Generalmente broken](usr-flags-atomic.html#overview). Otherwise compliant. |
| [RFC 6146](https://tools.ietf.org/html/rfc6146) | Stateful NAT64 | Cumple la mayor parte.<br />(Hereda detalles de cumplimiento del RFC 6145)<br />Tambien hemos sido incapaces de implementar [Políticas de Filtrado](https://github.com/NICMx/NAT64/issues/41). |
| [RFC 6384](http://tools.ietf.org/html/rfc6384) | FTP sobre NAT64 | [Sin cumplir todavía](https://github.com/NICMx/NAT64/issues/114). |
| [RFC 6791](https://tools.ietf.org/html/rfc6791) | Peculiaridades de ICMP | En resumen, este RFC quiere dos cosas: Un pool de direcciones IPv4 y una extensión del encabezado ICMP. Jool implementa la primera pero no la segunda. |
| [RFC 6877](http://tools.ietf.org/html/rfc6877) | 464XLAT | Implementado como SIIT-DC; vea abajo. |
| [draft-ietf-v6ops-siit-dc](https://tools.ietf.org/html/draft-ietf-v6ops-siit-dc-00) | SIIT-DC | Cumple totalmente. |
| [draft-ietf-v6ops-siit-dc-2xlat](https://tools.ietf.org/html/draft-anderson-v6ops-siit-dc-2xlat-00) | SIIT-DC Edge Translator | [Modo basado en Host.](https://tools.ietf.org/html/draft-ietf-v6ops-siit-dc-2xlat-00#section-3.1) No Implementado. |
| [draft-ietf-6man-deprecate-atomfrag-generation](https://tools.ietf.org/html/draft-ietf-6man-deprecate-atomfrag-generation-00) | Deprecación de Fragmento Atómica | Estrictamente hablando, el draft quiere que se deseche el concepto de fragmentos atómicos. Los implementamos -pobremente- como un [modo alternativo y su uso lo desalentamos completamente](usr-flags-atomic.html#overview). |
| [draft-anderson-v6ops-siit-eam](https://tools.ietf.org/html/draft-anderson-v6ops-siit-eam-02) | EAM | Cumple totalmente. |

Por favor [haznos saber](https://github.com/NICMx/NAT64/issues) si encuentras problemas de cumplimiento adicionales o RFCs/drafts que no hayamos considerado.

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

Red Hat y CentOS muestran un warning debido a un error entre el kernel de base usado en Red Hat y el de Debian. <a href="https://github.com/NICMx/NAT64/issues/105" target="_blank">Estamos buscando aun cómo eliminarlo</a>, pero este mensaje no es crítico porque no nos ha ocasionado problemas durante las pruebas.
