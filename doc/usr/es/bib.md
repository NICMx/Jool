---
language: es
layout: default
category: Documentation
title: BIB
---

[Documentación](documentation.html) > [Ejemplos de uso](documentation.html#ejemplos-de-uso) > [Stateful NAT64](mod-run-stateful.html) > BIB

# BIB

El _Binding Information Base_ (BIB) es una colección de tablas en un *Stateful NAT64*. Su especificación detallada se encuentra en la [Sección 3.1, del RFC 6146 ](http://tools.ietf.org/html/rfc6146#section-3.1).

A modo de breve introducción podemos decir que los registros en esta base de datos mapean las direcciones de transporte de la conexión de un nodo IPv6 a la dirección de transporte que Jool está usando para enmascararlo en  IPv4. Por ejemplo, si el siguiente mapeo existe en tu NAT64:


| Dirección IPv6 de Transporte | Dirección IPv4 de Transporte | Protocol |
|------------------------------|------------------------------|----------|
| 6::6#66                      | 4.4.4.4#44                   | TCP      |


Entonces los nodos IPv4 pueden encontrar el servicio TCP publicado en 6::6 por el puerto 66, enviando una solicitud a 4.4.4.4 por el puerto 44. En otra palabras, Jool engaña a los nodos IPv4 haciendoles pensar que 6::6#66 es 4.4.4.4#44.

* LLamamos "registro BIB" a un registro en la tabla BIB (ej. el identificador de una máscara).
* Llamamos "tabla BIB" a una colección de registros que comparten un protocolo. Hay tres protocolos soportados(TCP, UDP y ICMP), como resultado Jool tiene tres tablas BIB.
* Llamamos "BIB" a la colección de las tres tablas BIB de Jool.

Hay dos tipos de registros BIB:

* Estáticos: Los creas manualmente, para publicar un servicio IPv6 hacia la Internet IPv4. Ésto es análogo al [redireccionamiento de puertos](http://es.wikipedia.org/wiki/Redirecci%C3%B3n_de_puertos) href="http://en.wikipedia.org/wiki/Port_forwarding" en NATs normales.
* Dinámicos: Jool crea estos al vuelo. Esto se tiene que hacer por que las conecciones IPv6 iniciadas también necesitan máscaras IPv4(de otra manera no serían capaces de recibir respuestas).

Ve la [introducción](static-bindings.html) o el [material de referencia](usr-flags-bib.html) para obtener información de cómo crear y destruir registros manualmente. Ve [`--address-dependent-filtering`](usr-flags-global.html#filtrado-dependiente-de-direccion) si crees que los registros dinámicos son peligrosos.

