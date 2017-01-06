#!/bin/bash

# Initialize testing framework
source framework.sh
sudo modprobe jool disabled
COMMAND=jool


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




printf "\n\n--TOS - Valid input tests\n\n"
OPTS="--tos"
VALUES=( 0 255 1 000000000000150,9999 )
RETURNS=( 1 1 1 1)
OUTPUTS=( "" "" "" "" )
test_options

printf "\n\n--TOS - Invalid input tests\n\n"
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

printf "\n\n--zeroize-traffic-class - Valid input tests\n"
OPTS="--zeroize-traffic-class"
VALUES=( true 1 Yes "                   ON" NO oFF FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n--zeroize-traffic-class - Invalid input tests\n"
OPTS="--zeroize-traffic-class"
VALUES=( 00 True. Example @ $ ^ 2 )
RETURNS=( 0 0 0 0 0 0 0 )
test_options

printf "\n\n--mtu-plateaus - Valid input tests\n"
OPTS="--mtu-plateaus"
VALUES=( 1 1,1 65535 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9 1.5,10.2,8.9)
RETURNS=( 1 1 1 1 1 )
test_options

printf "\n--mtu-plateaus - Invalid input tests\n"
OPTS="--mtu-plateaus"
VALUES=( 0 "1, 1" 0,0,0,0 1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5 )
RETURNS=( 0 0 0 0 0)
test_options

printf "\n\n--UDP-TIMEOUT - Valid input tests\n\n"
OPTS="--udp-timeout"
VALUES=( 120 4294967 99999 000000000000000000000150 )
RETURNS=( 1 1 1 1)
OUTPUTS=( "" "" "" "" )
test_options

printf "\n\n--UDP-TIMEOUT - Invalid input tests\n\n"
OPTS="--udp-timeout"
VALUES=( 0 abc 99999999999999 1.0 4294968 )
RETURNS=( 0 0 0 0 0 )
OUTPUTS=( "" "" "" "" "" )
test_options

printf "\n\n--TCP-EST-TIMEOUT - Valid input tests\n\n"
OPTS="--tcp-est-timeout"
VALUES=( 7200 10000 4294967 000040000,000)
RETURNS=( 1 1 1 1 )
OUTPUTS=("" "" "" "" ) 
test_options

printf "\n\n--TCP-EST-TIMEOUT - Invalid input tests\n\n"
OPTS="--tcp-est-timeout"
VALUES=( 0 abc 7199 9999999999999 4294968 )
RETURNS=( 0 0 0 0 0 )
OUTPUTS=("" "" "" "" "")
test_options

printf "\n\n--TCP-TRANS-TIMEOUT - Valid input tests\n\n"
OPTS="--tcp-trans-timeout"
VALUES=( 240 10000 4294967 00000000550000,000 )
RETURNS=( 1 1 1 1 )
OUTPUTS=("" "" "" "" )
test_options

printf "\n\n--TCP-TRANS-TIMEOUT - Invalid input tests\n\n"
OPTS="--tcp-trans-timeout"
VALUES=( 0 abc 239 99999999999999 4294968 )
RETURNS=( 0 0 0 0 0 )
OUTPUTS=("" "" "" "" "")
test_options

printf "\n\n--ICMP-TIMEOUT - Valid input tests\n\n"
OPTS="--icmp-timeout"
VALUES=( 0 1000 4294967 00000000550000,000 )
RETURNS=( 1 1 1 1 )
OUTPUTS=("" "" "" "" )
test_options

printf "\n\n--ICMP-TIMEOUT - Invalid input tests\n\n"
OPTS="--icmp-timeout"
VALUES=( -1 abc 99999999999999 4294968 )
RETURNS=( 0 0 0 0 )
OUTPUTS=("" "" "" "")
test_options

printf "\n\n--fragment-arrival-timeout - Valid input tests\n\n"
OPTS="--fragment-arrival-timeout"
VALUES=( 2 4294967 1234567 000000000002,0001 )
RETURNS=( 1 1 1 1)
OUTPUTS=( "" "" "" "" )
test_options

printf "\n\n--fragment-arrival-timeout - Invalid input tests\n\n"
OPTS="--fragment-arrival-timeout"
VALUES=( 0 prueba 999999999999999999999999 4294968 )
RETURNS=( 0 0 0 0 )
OUTPUTS=( "" "" "" "" )
test_options

printf "\n\n--maximum-simultaneous-opens - Valid input tests\n\n"
OPTS="--maximum-simultaneous-opens"
VALUES=( 0 4294967295 1 000000000000123456789,9999 )
RETURNS=( 1 1 1 1)
OUTPUTS=( "" "" "" "" )
test_options

printf "\n\n--maximum-simultaneous-opens - Invalid input tests\n\n"
OPTS="--maximus-simultaneous-opens"
VALUES=( -1 abc 4294967296 10000000000000009 )
RETURNS=( 0 0 0 0 )
OUTPUTS=( "" "" "" "" )
test_options

printf "\n\n--source-icmpv6-errors-better - Valid input tests\n\n"
OPTS="--source-icmpv6-errors-better"
VALUES=( true 1 Yes "                   ON" NO oFF FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n\n--source-icmpv6-errors-better - Invalid input tests\n\n"
OPTS="--source-icmpv6-errors-better"
VALUES=( 00 True. Example @ $ ^ 2 )
RETURNS=( 0 0 0 0 0 0 0 )
test_options

printf "\n\n--logging-bib - Valid input tests\n\n"
OPTS="--logging-bib"
VALUES=( true 1 Yes "                   ON" NO oFF FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n\n--logging-bib - Invalid input tests\n\n"
OPTS="--logging-bib"
VALUES=( 00 True. Example @ $ ^ 2 )
RETURNS=( 0 0 0 0 0 0 0 )
test_options

printf "\n\n--logging-session - Valid input tests\n\n"
OPTS="--logging-session"
VALUES=( true 1 Yes "                   ON" NO oFF FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n\n--logging-session - Invalid input tests\n\n"
OPTS="--logging-session"
VALUES=( 00 True. Example @ $ ^ 2 )
RETURNS=( 0 0 0 0 0 0 0 )
test_options


printf "\n\n--address-dependent-filtering - Valid input tests\n\n"
OPTS="--address-dependent-filtering"
VALUES=( true 1 Yes "                   ON" NO oFF FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n\n--address-dependent-filtering - Invalid input tests\n\n"
OPTS="--address-dependent-filtering"
VALUES=( 00 True. Example @ $ ^ 2 )
RETURNS=( 0 0 0 0 0 0 0 )
test_options

printf "\n\n--drop-icmpv6-info - Valid input tests\n\n"
OPTS="--drop-icmpv6-info"
VALUES=( true 1 Yes "                   ON" NO oFF FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n\n--drop-icmpv6-info - Invalid input tests\n\n"
OPTS="--drop-icmpv6-info"
VALUES=( 00 True. Example @ $ ^ 2 )
RETURNS=( 0 0 0 0 0 0 0 )
test_options

printf "\n\n--drop-externally-initiated-tcp - Valid input tests\n\n"
OPTS="--drop-externally-initiated-tcp"
VALUES=( true 1 Yes "                   ON" NO oFF FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n\n--drop-externally-initiated-tcp - Invalid input tests\n\n"
OPTS="--drop-externally-initiated-tcp"
VALUES=( 00 True. Example @ $ ^ 2 )
RETURNS=( 0 0 0 0 0 0 0 )
test_options

printf "\n\n--handle-rst-during-fin-rcv - Valid input tests\n\n"
OPTS="--handle-rst-during-fin-rcv"
VALUES=( true 1 Yes "                   ON" NO oFF FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n\n--handle-rst-during-fin-rcv - Invalid input tests\n\n"
OPTS="--handle-rst-during-fin-rcv"
VALUES=( 00 True. Example @ $ ^ 2 )
RETURNS=( 0 0 0 0 0 0 0 )
test_options

printf "\n\n--f-args - Valid input tests\n"
OPTS="--f-args"
VALUES=( 0 "       1" 00000015 8,2 )
RETURNS=( 1 1 1 1 )
test_options

printf "\n--f-args - Invalid input tests\n"
OPTS="--f-args"
VALUES=( 10000 "1 0"  F abc "10101010" 16 -1)
RETURNS=( 0 0 0 0 0 0 0 )
test_options

printf "\n\n--ss-enabled - Valid input tests\n"
OPTS="--ss-enabled"
VALUES=( true 1 Yes "    ON" NO Off FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n--ss-enabled - Invalid input tests\n"
OPTS="--ss-enabled"
VALUES=( 00 True. Example @ $ ^ 2 )
RETURNS=( 0 0 0 0 0 0 0 )
test_options

printf "\n\n--ss-flush-asap - Valid input tests\n"
OPTS="--ss-flush-asap"
VALUES=( true 1 Yes "    ON" NO Off FaLsE )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n--ss-flush-asap - Invalid input tests\n"
OPTS="--ss-flush-asap"
VALUES=( 00 True. Example @ $ ^ 2 )
RETURNS=( 0 0 0 0 0 0 0 )
test_options

printf "\n\n--ss-flush-deadline - Valid input tests\n"
OPTS="--ss-flush-deadline"
VALUES=( 512 0 4294967295 9.9  00000123 )
RETURNS=( 1 1 1 1 1 )
test_options

printf "\n--ss-flush-deadline - Invalid input tests\n"
OPTS="--ss-flush-deadline"
VALUES=( -1 9999999999999999999 4294967296 True. "2 2"  .2 )
RETURNS=( 0 0 0 0 0 0 )
test_options

printf "\n\n--ss-capacity - Valid input tests\n"
OPTS="--ss-capacity"
VALUES=( 512 0 4294967295 9.9  00000123 )
RETURNS=( 1 1 1 1 1 )
test_options

printf "\n--ss-capacity - Invalid input tests\n"
OPTS="--ss-capacity"
VALUES=( -1 9999999999999999999 4294967296 True. "2 2"  .2 )
RETURNS=( 0 0 0 0 0 0 )
test_options

printf "\n\n--ss-max-payload - Valid input tests\n"
OPTS="--ss-max-payload"
VALUES=( 1452 0 1 2048 00000123 2000.00 0.0 )
RETURNS=( 1 1 1 1 1 1 1 )
test_options

printf "\n--ss-max-payload - Invalid input tests\n"
OPTS="--ss-max-payload"
VALUES=( -1 999999999999 2049 True. "2 2"  .2 )
RETURNS=( 0 0 0 0 0 0 )
test_options








sudo modprobe -r jool
print_summary
