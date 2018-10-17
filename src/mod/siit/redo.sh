sudo modprobe -r jool_siit && \
	make && \
	sudo make modules_install && \
	sudo dmesg -C && \
	sudo modprobe jool_siit && \
	echo "Success."
