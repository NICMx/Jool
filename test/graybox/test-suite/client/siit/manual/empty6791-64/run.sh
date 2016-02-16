sudo modprobe graybox

graybox -ga --numArray 4,5,6,10,11,32,33,34,38,39
graybox -ra --pkt e6791-64-receiver-nofrag.pkt
graybox -sa --pkt e6791-64-sender-nofrag.pkt
sleep 0.1s
sudo modprobe -r graybox

dmesg

