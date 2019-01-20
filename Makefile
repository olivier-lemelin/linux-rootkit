obj-m += rootkit.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm rootkit.mod.c rootkit.mod.o rootkit.o modules.order Module.symvers rootkit.ko
