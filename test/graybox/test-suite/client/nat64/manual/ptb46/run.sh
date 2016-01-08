sudo modprobe graybox

graybox -ra --pkt ptb46-receiver-nofrag.pkt 
graybox -sa --pkt ptb46-session-nofrag.pkt 
graybox -sa --pkt ptb46-sender-nofrag.pkt 

sleep 0.1s
sudo modprobe -r graybox
dmesg
