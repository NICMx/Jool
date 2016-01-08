sudo modprobe graybox

graybox -ra --pkt e6791-66-receiver-nofrag.pkt
graybox -sa --pkt e6791-66-sender-nofrag.pkt
sleep 0.1s
sudo modprobe -r graybox

dmesg

