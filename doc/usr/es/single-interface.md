---
language: es
layout: default
category: Documentation
title: Ejecución Alterna de Stateful
---

[Doc](documentation.html) > [Otros](documentation.html#otros) > Interfaz Única

# Interfaz Única

Jool puede ver paquetes viniendo desde cualquier interfaz y puede enviar paquetes mediante cualquier interfaz (excepto loopback). Por lo tanto, es capaz de servir ambos protocolos en la misma interfaz.

![Fig.1 - NAT64 en una sola interfaz](../images/network/alternate.svg)

Esta es la misma configuración que en el [Ejemplo de uso de Stateful NAT64](run-nat64.html), excepto que todos los nodos involucrados comparten un mismo cable.

_A_ y  _V_ son configurados exactamente como en sus contrapartes del ejemplo Stateful, de modo que se omitirán sus comandos. Lo único que es diferente es _T_ ahora teniendo todas sus direcciones en la misma interfaz:

	user@T:~# service network-manager stop
	user@T:~# 
	user@T:~# /sbin/ip link set eth0 up
	user@T:~# /sbin/ip address add 2001:db8::1/96 dev eth0
	user@T:~# /sbin/ip address add 203.0.113.1/24 dev eth0
	user@T:~# 
	user@T:~# sysctl -w net.ipv4.conf.all.forwarding=1
	user@T:~# sysctl -w net.ipv6.conf.all.forwarding=1
	user@T:~# ethtool --offload eth0 gro off
	user@T:~# ethtool --offload eth0 lro off
	user@T:~# 
	user@T:~# /sbin/modprobe jool pool6=64:ff9b::/96

A pesar de que _A_ y _V_ están directamente conectados, no pueden interactuar porque hablan distintos protocolos. Esto es, a menos de que _T_ traduzca su conversación:

	user@A:~$ /bin/ping6 64:ff9b::203.0.113.16
	PING 64:ff9b::203.0.113.16(64:ff9b::cb00:7110) 56 data bytes
	64 bytes from 64:ff9b::cb00:7110: icmp_seq=1 ttl=63 time=10.0 ms
	64 bytes from 64:ff9b::cb00:7110: icmp_seq=2 ttl=63 time=8.16 ms
	64 bytes from 64:ff9b::cb00:7110: icmp_seq=3 ttl=63 time=8.39 ms
	64 bytes from 64:ff9b::cb00:7110: icmp_seq=4 ttl=63 time=5.64 ms
	^C
	--- 64:ff9b::203.0.113.16 ping statistics ---
	4 packets transmitted, 4 received, 0% packet loss, time 3003ms
	rtt min/avg/max/mdev = 5.645/8.057/10.025/1.570 ms

