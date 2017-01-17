obj-m := port_connection.o
KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	rm -rf *.ko
	rm -rf *.cmd
	rm -rf *.o
	make -C $(KERNELDIR) M=$(PWD) modules
