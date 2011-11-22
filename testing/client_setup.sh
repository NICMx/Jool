ip -6 addr del fe80::a00:27ff:fefe:633a/64 dev eth0
ifconfig eth0 inet6 add fec0::2/64
ip route add fec0::1 dev eth0
ip -6 route add default via fec0::1
ip route del fe80::/64
ip -6 route del fec0::/64
