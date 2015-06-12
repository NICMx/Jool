---
layout: documentation
title: Documentación - EAMT
---

[Documentación](esp-doc-index.html) > [Ejemplos de uso](esp-doc-index.html#ejemplos-de-uso) > [SIIT + EAM](esp-mod-run-eam.html) > EAMT

# EAMT

La tabla EAMT (_Explicit Address Mappings Table__) por sus siglas en inglés, es una colección de registros en un dispositivo SIIT ls cual describe como las diferentes direcciones deben de ser traducidas. A partir del 2015-03-02, su revisión mas nueva es el [draft-anderson-v6ops-siit-eam](https://tools.ietf.org/html/draft-anderson-v6ops-siit-eam-02).

Aquí se encuentra un ejemplo de una tabla EAMT:

| IPv4 Prefix     |     IPv6 Prefix      |
|-----------------|----------------------|
| 192.0.2.1/32    | 2001:db8:aaaa::5/128 |
| 198.51.100.0/24 | 2001:db8:bbbb::/120  |
| 203.0.113.8/29  | 2001:db8:cccc::/125  |

Un registro EAMT está compuesto de un prefijo IPv4 y un prefijo IPv6. Cuando una dirección esta siendo traducida, su prefijo es literalmente reemplazado de acuerdo a la tabla. En la implementación de Jool, todos los registros son bidireccionales.

El primer registro mostrado es el caso más simple. Por que no tiene prefijo, el registro literalmente dice "La dirección `192.0.2.1` debe de ser siempre traducida como `2001:db8:aaaa::5`, y vice versa". Ya sea que la direccion es origen,destino, o caiga dentro del paquete interno de un error ICMP, no importa. La representación IPv6 de `192.0.2.1` es `2001:db8:aaaa::5`, y la representación IPv4 de `2001:db8:aaaa::5` es `192.0.2.1`. Punto.

La segunda entrada es mas interesante. Porque hay  Because hay un byte entero de sufijo, el registro esta diciendo "`198.51.100.x` debera ser tradicida como `2001:db8:bbbb::x`, y vice versa. _x_ es cualquier numero entre 0-255."

Como en:

- `198.51.100.0` <-> `2001:db8:bbbb::0`
- `198.51.100.1` <-> `2001:db8:bbbb::1`
- `198.51.100.2` <-> `2001:db8:bbbb::2`
- ...
- `198.51.100.254` <-> `2001:db8:bbbb::fe`
- `198.51.100.255` <-> `2001:db8:bbbb::ff`

Esta forma puede ayudarte a simplificar la configuración cuando tienes muchas direcciones para traducir; el sufijo siempre es preservado, el punto es un solo registro EAMT puede describir la traducción de una red entera.

(También, un solo registro EAMT describiendo un /16 mucho mas eficiente que los 65536 registros atómicos equivalentes.)

El reemplazo de prefijo es hecho a nivel de bits. El tercer registro ejemplifica esto: La dirección `203.0.113.8` se convierte en `2001:db8:cccc::`, no en `2001:db8:cccc::8`. Esto es porque la forma binaria de `.8` es `00001000`, y el uno se encuentra en el lado del prefijo. Estos son algunos otros mapeos generados por el registro:

- `203.0.113.9` <-> `2001:db8:cccc::1`
- `203.0.113.10` <-> `2001:db8:cccc::2`
- `203.0.113.12` <-> `2001:db8:cccc::4`
- `203.0.113.15` <-> `2001:db8:cccc::7`

Los registros EAMT no se pueden intersectar. Si Jool no encuentra una coincidencia en la tabla para una dirección, intenta traducir basado en el prefijo [`pool6`](usr-flags-pool6.html). Si eso tambien falla, el paquete es devuelto al kernel (ej. Se asume que el paquete no se intentaba traducir).

Ve la [demostración](esp-mod-run-eam.html) o el [material de referencia](esp-usr-flags-eamt.html) para obtener información de como crear y destruir registros manualmente.
