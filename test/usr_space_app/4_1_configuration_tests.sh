#!/bin/bash

# Initialize testing framework
source library.sh
sudo modprobe jool disabled
COMMAND=jool


# Aquí hay un ejemplo completo de una prueba (aunque le faltan test cases
# extremos).
# Por cada VALUES, test_options va a correr Jool usando una concatenación
# entre OPTS y VALUES[i]. Por cada VALUES va a esperar que el programa regrese
# el código de error RETURNS[i] y que imprima en standard output o standard
# error OUTPUTS[i]. Tanto RETURNS como OUTPUTS son opcionales
# (pero obviamente necesitas al menos uno para hacer una prueba).

### Filtering UDP
OPTS="--udp-timeout"
VALUES=( -1 abc 120 )
RETURNS=( 0 0 1 )
# Cadena vacía significa que no va validar nada.
OUTPUTS=( "is not a number" "is not a number" "" )
test_options

# Todas las pruebas listadas abajo y en los otros archivos están
# desactualizadas.
# Hay que actualizarlas, quitar las que ya no apliquen y agregar cosas si
# faltan.

### Filtering TCP
OPTS="--tcp-est-timeout"
VALUES=( 500 abc 7200 )
RETURNS=( 234 1 244 )
test_options

OPTS="--tcp-trans-timeout"
VALUES=( 100 gfh 1000 )
RETURNS=( ERR1008 ERR1007 success )
test_options

### Filtering ICMP
OPTS="--icmp-timeout"
VALUES=( 66000 abc 1000 )
RETURNS=( ERR1008 ERR1007 success )
test_options

### Filtering TOS
OPTS="--tos"
VALUES=( -1 abc 100 )
RETURNS=( ERR1008 ERR1007 success )
test_options

## Filtering filter
OPTS="--address-dependent-filtering"
VALUES=( abc 10 0 )
RETURNS=( ERR1006 ERR1006 success )
test_options

OPTS="--drop-icmpv6-info"
VALUES=( ' ' 10 "false" )
RETURNS=( ERR1006 ERR1006 success )
test_options

OPTS="--drop-externally-initiated-tcp"
VALUES=( 22 10 on )
RETURNS=( ERR1006 ERR1006 success )
test_options

### Translate TC 
OPTS="--zeroize-traffic-class"
VALUES=( null 10 off )
RETURNS=( ERR1006 ERR1006 success )
test_options

### Translate TOS 
OPTS="--override-tos"
VALUES=( null 10 "true" )
RETURNS=( ERR1006 ERR1006 success )
test_options

### Reject empty MTU lists
OPTS="--mty-plateaus"
VALUES=( '' )
RETURNS=( ERR1009 )
KERNMSG=( NOERR )
test_options

### Reject zeroes in MTU values
OPTS="--mtu-plateaus"
VALUES=( '0' )
RETURNS=( ERR1000 )
KERNMSG=( ERR1002 )
test_options


sudo modprobe -r jool
print_summary
