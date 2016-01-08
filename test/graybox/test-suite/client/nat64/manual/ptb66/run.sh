sudo modprobe graybox

graybox -ra --pkt ptb66-receiver-nofrag.pkt 
graybox -sa --pkt ptb66-session-nofrag.pkt 
graybox -sa --pkt ptb66-sender-nofrag.pkt 

sleep 0.1s
sudo modprobe -r graybox
dmesg

