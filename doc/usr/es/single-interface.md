---
language: es
layout: default
category: Documentation
title: Ejecución Alterna de Stateful
---

[Doc](documentation.html) > [Otros](documentation.html#otros) > Interfáz Única

#Interfáz Única

Esta sección está aquí is here solo para decirte que si quieres que tu SIIT o NAT64 brinden servicio a ambos protocolos en la misma interfáz, aun estás cubierto. Jool puede ver paquetes viniendo desde cualquier interfaz y puede enviar paquetes mediante cualquier interfaz. (aunque ignora, el loopback).

![Fig.1 - Single interface NAT64](../images/network/alternate.svg)

Esta es la misma configuración que en el [Ejemplo de uso de Stateful NAT64](run-nat64.html), excepto por el hecho de que todo mundo ahora esta compartiendo el mismo cable, y tambien removí los nodos reduntantes por que entiendes el punto.

_A_ y  _V_ son configurados exactamente como en sus contrapartes del ejemplo Stateful, asi que voy a brincarme sus comandos. Lo único que es diferente es _T_ ahora teniendo todas sus direcciones en la misma interfáz:

	user@T:~# service network-manager stop
	user@T:~# 
	user@T:~# /sbin/ip link set eth0 up
	user@T:~# /sbin/ip address add 2001:db8::1/96 dev eth0
	user@T:~# /sbin/ip address add 203.0.113.1/24 dev eth0
	user@T:~# /sbin/ip address add 203.0.113.2/24 dev eth0
	user@T:~# 
	user@T:~# ethtool --offload eth0 tso off
	user@T:~# ethtool --offload eth0 ufo off
	user@T:~# ethtool --offload eth0 gso off
	user@T:~# ethtool --offload eth0 gro off
	user@T:~# ethtool --offload eth0 lro off
	user@T:~# 
	user@T:~# /sbin/modprobe jool pool6=64:ff9b::/96 pool4=203.0.113.2



Así que básicamente, _A_ y _V_ comparten el mismo cable, pero de todos no pueden hablar por que no hablan el mismo lenguaje. Esto es, a menos de que le soliciten a _T_ traducir su pequeña conversación:

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
