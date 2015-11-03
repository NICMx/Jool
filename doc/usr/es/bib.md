---
language: es
layout: default
category: Documentation
title: BIB
---

[Documentación](documentation.html) > [NAT64 en detalle](documentation.html#nat64-en-detalle) > BIB

# BIB

## Índice

1. [¿Qué es la BIB?](#qu-es-la-bib)
2. [Terminología](#terminologa)
4. [Ejemplos](#ejemplos)
	1. [Registro 01](#registro-01)
	2. [Registro 02](#registro-02)
	3. [Registro 03](#registro-03)
5. [Lecturas adicionales](#lecturas-adicionales)

## ¿Qué es la BIB?

La _Binding Information Base_ (BIB) es una colección de tablas en un Stateful NAT64, y está definida formalmente en [la sección 3.1 del RFC 6146](http://tools.ietf.org/html/rfc6146#section-3.1).

Es una base de datos que guarda mapeos. Cada registro señala la relación entre la dirección de transporte de un socket en un nodo IPv6 y la dirección de transporte IPv4 que Jool está usando para enmascararlo.

> ![Nota](../images/bulb.svg) Estrictamente hablando, una "dirección de transporte" es una dirección IP junto con un puerto. El hecho de que incluye un puerto tiende a implicar que se trata del descriptor de una conexión TCP o UDP.
> 
> Dado que, para fines de implementación, ICMP se comporta como un protocolo de capa 4, también extendemos la expresión "dirección de transporte" hacia ICMP. ICMP no tiene puertos, de modo que cuando decimos "dirección de transporte de ICMP" realmente nos referimos a una dirección de IP más un identificador de ICMP.

> ![Advertencia](../images/warning.svg) Nótese que BIB solamente expone información sobre nodos IPv6; no se puede decir que una entrada BIB también pueda señalar el mapeo entre un socket IPv4 y la dirección de transporte IPv6 que Jool está usando para "enmascararlo".
> 
> Esta información puede encontrarse en las [tablas de sesión](usr-flags-session.html).

Dado que una máscara es necesariamente una dirección que le pertenece a Jool, la dirección de transporte IPv4 normalmente tiene que ser parte de [pool4](pool4.html).

> ![Nota](../images/bulb.svg) Pueden haber registros BIB que contengan direcciones que no le pertenecen a pool4 si estas direcciones fueron removidas recientemente de pool4 utilizando la opción [`--quick`](usr-flags-quick.html).

## Terminología

* **Registro BIB** es un registro en la tabla BIB y contiene tres campos: Una dirección de transporte IPv6, la máscara IPv4 que se está usando para enmascararlo y el tipo (dinámico o estático).
	- Cuando un nodo IPv6 abre comunicación con un nodo de IPv4, Jool tiene que crear un mapeo para que la comunicación pueda suceder. Cuando se generan automáticamente conforme se necesitan (y se eliminan automáticamente conforme expiran), se dice que son "registros **dinámicos**".
	- Mapeos creados manualmente pueden ser usados para dar nombres permanentes a sockets IPv6. Estas máscaras no expiran automáticamente y nodos IPv4 pueden usarlas para iniciar comunicación. Esto es análogo a [redireccionamiento de puertos](https://es.wikipedia.org/wiki/Redirecci%C3%B3n_de_puertos) en NATs normales, y se les llama "registros **estáticos**".
* **Tabla BIB** es una colección de registros que comparten un protocolo. Hay tres protocolos soportados (TCP, UDP y ICMP), de modo que Jool tiene tres tablas BIB.
* **BIB** es la colección de las tres tablas BIB.

## Ejemplos

Salvo por la columna "No.Registro", así es como puede verse una tabla BIB en un NAT64:

| No.Registro | Dirección de Transporte IPv6 | Dirección de Transporte IPv4 | Tipo     |
|-------------|------------------------------|------------------------------|----------|
|     01      | 2001:db8::1#40000            | 192.0.2.4#40000              | Dinámico |
|     02      | 2001:db8::2#40000            | 198.51.100.10#50000          | Dinámico |
|     03      | 2001:db8::3#80               | 203.0.113.43#80              | Estático |


### Registro 01

Este registro indica que el nodo 2001:db8::1 (utilizando el puerto 40000) se está comunicando con IPv4. El NAT64 se encuentra engañando a los nodos de IPv4, haciéndoles pensar que la dirección de 2001:db8::1 es 192.0.2.4.

Nuevamente cabe mencionar que esto no nos dice con quién está interactuando 2001:db8::1; el registro solamente habla sobre 2001:db8::1.

### Registro 02

02 es similar al 01, con la excepción de que el puerto de la máscara es diferente al original. Como se menciona en [pool4](pool4.html), un NAT64 no se interesa en preservar puertos, de modo que es más natural ver registros como este que como el anterior.

El registro enuncia que existe un socket en el puerto 40000 de la dirección 2001:db8::2, y que al menos un nodo de IPv4 cree que es 50000 en la dirección 198.51.100.10.

### Registro 03

Este registro fue dado de alta manualmente. Observando los puertos es posible sospechar que se trata de un servicio HTTP IPv6 que el administrador ha hecho disponible también para IPv4.

Dado que es estático y por lo tanto no va a caducar, clientes de IPv4 pueden fiablemente usar 203.0.113.43#80 para alcanzar este servicio.

## Lecturas adicionales

1. [`--bib`](usr-flags-bib.html) puede usarse para dar de alta registros estáticos.
2. [`--address-dependent-filtering`](usr-flags-global.html#address-dependent-filtering) es una capa de seguridad que se puede aplicar para limitar registros dinámicos.

