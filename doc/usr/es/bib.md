---
language: es
layout: default
category: Documentation
title: BIB
---

[Documentación](documentation.html) > [Ejemplos de uso](documentation.html#ejemplos-de-uso) > [Stateful NAT64](mod-run-stateful.html) > BIB

# BIB

## Índice

1. [Qué es la BIB?](#qu-es-la-bib)
2. [Estructura](#estructura)
3. [Tipos](#tipos)
4. [Ejemplos](#ejemplos)<br />
	a) [Registro 01](#registro-01)<br />
	b) [Registro 02](#registro-02)<br />
	c) [Registro 03](#registro-03)
5. [Lecturas adicionales](#lecturas-adicionales)

## Qué es la BIB?

El _Binding Information Base_ (BIB) es una colección de tablas en el *Stateful NAT64*. Aunque este concepto nace con los NATs y está definido en el [RFC 2263, 1999](https://tools.ietf.org/html/rfc2663). 

La podríamos llamar Base de Datos de Asociaciones o Enlaces porque en ella se guardará por pares la asociación (dirección IPv6, puerto IPv6) con  (dirección IPv4, puerto IPv4) si es una paquete de UDP o TCP. A esas duplas se le llaman [direcciones de transporte](http://tools.ietf.org/html/rfc6146#section-1.2). Cuando es un paquete de ICMP, se guardan los pares (dirección IPv6, identificador IPv6) con  (dirección IPv4, identificador IPv4). Para conocer todos los detalles sobre la BIB lee [la Sección 3.1, del RFC 6146 ](http://tools.ietf.org/html/rfc6146#section-3.1).

Dicho de otra manera, podemos decir que los registros en esta base de datos mapean las _direcciones de transporte_ de la conexión de un nodo IPv6 a la _dirección de transporte_ que Jool está usando para enmascarar éste en IPv4 en los protocolos UDP y TCP. Y mapeará la dupla (IP, identificador) de la conexión de un nodo IPv6 a la dupla (IP, identificador)  que Jool está usando para enmascarar éste en IPv4 si es un mensaje de ICMP.

## Estructura

* **Registro BIB** es un registro en la tabla BIB y está compuesto por duplas.
* **Tabla BIB** es una colección de registros que comparten un protocolo. Dado que hay tres protocolos soportados (TCP, UDP y ICMP) por el RFC 6146, como resultado Jool tiene tres tablas BIB.
* **BIB** es la colección de las tres tablas BIB de Jool.

## Tipos

Hay dos tipos de registros BIB:

* Dinámicos: Jool crea estos al iniciar la comunicación de IPv6 a IPv4, para acceder a lo servicios de IPv4.
* Estáticos: Los puedes dar de alta manualmente, para publicar un servicio IPv6 hacia la Red de IPv4, ya sea privada o pública. Esto es análogo al [redireccionamiento de puertos](http://es.wikipedia.org/wiki/Redirecci%C3%B3n_de_puertos) en NATs.

## Ejemplos

Por ejemplo, si los siguiente mapeos existen en tu NAT64:

| No.Registro| Dirección IPv6 de Transporte | Dirección IPv4 de Transporte | Protocol |
|----------- |------------------------------|------------------------------|----------|
|    01      | 6::6#66                      | 4.4.4.4#44                   | TCP      |
|    02      |            |                              | TCP      |
|    03      | 2001:db8::8#40000            | 203.0.113.2#                 | TCP      |


### Registro 01

Entonces los nodos IPv4 pueden encontrar el servicio TCP publicado en 6::6 por el puerto 66, enviando una solicitud a 4.4.4.4 por el puerto 44. En otras palabras, Jool engaña a los nodos IPv4 haciendoles pensar que 6::6#66 es 4.4.4.4#44.

### Registro 02

### Registro 03

## Lecturas adicionales

Si quieres aprender sobre:

1. Cómo crear y destruir registros manualmente, ve a [mapeo estático](static-bindings.html) o consulta [usando la opción BIB](usr-flags-bib.html).
2. Cómo restringir el uso de los registros dinámicos, ve a [`--address-dependent-filtering`](usr-flags-global.html#address-dependent-filtering).

