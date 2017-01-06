#!/bin/bash

# Initialize testing framework
source framework.sh
sudo modprobe jool_siit disabled
COMMAND=jool_siit


# Aquí hay un ejemplo completo de una prueba (aunque le faltan test cases
# extremos).
# Por cada VALUES, test_options va a correr Jool usando una concatenación
# entre OPTS y VALUES[i]. Por cada VALUES va a esperar que el programa regrese
# el código de error RETURNS[i] y que imprima en standard output o standard
# error OUTPUTS[i]. Tanto RETURNS como OUTPUTS son opcionales
# (pero obviamente necesitas al menos uno para hacer una prueba).
# OPTS="--udp-timeout"
# VALUES=( 120 4294967 99999 )
# RETURNS=( 1 1 1 )
# OUTPUTS=( "is not a number" "is not a number" "" )
# Cadena vacía significa que no va validar nada.
# Todas las pruebas listadas abajo y en los otros archivos están
# desactualizadas.
# Hay que actualizarlas, quitar las que ya no apliquen y agregar cosas si
# faltan.

printf "\n\n--tos - Valid input tests\n\n"
OPTS="--tos"
VALUES=( 0 255 1 000000000000150,9999 )
RETURNS=( 1 1 1 1)
OUTPUTS=( "" "" "" "" )
test_options

printf "\n\n--tos - Invalid input tests\n\n"
OPTS="--tos"
VALUES=( -1 abc 99999999999999 256 )
RETURNS=( 0 0 0 0 )
OUTPUTS=( "" "" "" "" )
test_options

printf "\n\n--override-tos - Valid input tests\n\n"
OPTS="--override-tos"
VALUES=( true 1 Yes "                   ON" NO oFF FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n\n--override-tos - Invalid input tests\n\n"
OPTS="--override-tos"
VALUES=( 00 True. Example @ $ ^ 2 )
RETURNS=( 0 0 0 0 0 0 0 )
test_options

printf "\n\n--mtu-plateaus - Valid input tests\n\n"
OPTS="--mtu-plateaus"
VALUES=( 1 1,1 65535 1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4 1.5,2.0,4.6,3.3,0.2 )
RETURNS=( 1 1 1 1 1 )
test_options

printf "\n\n--mtu-plateaus - Invalid input tests\n\n"
OPTS="--mtu-plateaus"
VALUES=( True. @ 0 "1, 2" 0,0,0,0,0 1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5  )
RETURNS=( 0 0 0 0 0 0 )
test_options

printf "\n\n--zeroize-traffic-class - Valid input tests\n\n"
OPTS="--zeroize-traffic-class"
VALUES=( true 1 Yes "       ON" NO oFF FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n\n--zeroize-traffic-class - Invalid input tests\n\n"
OPTS="--zeroize-traffic-class"
VALUES=( 00 True. Example @ $ ^ 2  )
RETURNS=( 0 0 0 0 0 0 0 )
test_options


printf "\n\n--amend-udp-checksum-zero - Valid input tests\n\n"
OPTS="--amend-udp-checksum-zero"
VALUES=( true 1 Yes "       ON" NO oFF FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n--amend-udp-checksum-zero - Invalid input tests\n\n"
OPTS="--amend-udp-checksum-zero"
VALUES=( 00 True. Example @ $ ^ 2  )
RETURNS=( 0 0 0 0 0 0 0 )
test_options

printf "\n\n--randomize-rfc6791-addresses - Valid input tests\n\n"
OPTS="--randomize-rfc6791-addresses"
VALUES=( true 1 Yes "       ON" NO oFF FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n--randomize-rfc6791-addresses - Invalid input tests\n\n"
OPTS="--randomize-rfc6791-addresses"
VALUES=( 00 True. Example @ $ ^ 2  )
RETURNS=( 0 0 0 0 0 0 0 )
test_options

printf "\n\n--eam-hairpin-mode - Valid input tests\n\n"
OPTS="--eam-hairpin-mode"
VALUES=( 0 1 2 0.1 1. 2,3 00 02  )
RETURNS=( 1 1 1 1 1 1 1 1 )
test_options

printf "\n--eam-hairpin-mode - Invalid input tests\n\n"
OPTS="--eam-hairpin-mode"
VALUES=( 3 dos -1  )
RETURNS=( 0 0 0 )
test_options

printf "\n\n--rfc6791v6-prefix - Valid input tests\n\n"
OPTS="--rfc6791v6-prefix"
VALUES=( null 2001:: 2:2:2:2:2:2:2:2 FFFF::FFFF aBcD:cDeF:0123:2345:1212:5678:7889:9098 ff64::10.0.0.1 ::1.2.3.4 :: )
RETURNS=( 1 1 1 1 1 1 1 1)
test_options

printf "\n--rfc6791v6-prefix - Invalid input tests\n\n"
OPTS="--rfc6791v6-prefix"
VALUES=( 127.0.0.1 00 True. Example @ $ ^ 2  )
RETURNS=( 0 0 0 0 0 0 0 0 )
test_options



sudo modprobe -r jool_siit
print_summary
