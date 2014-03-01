obj-m = playground.o
all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules

clean:
	rm -rf Module.symvers playground.ko playground.mod.c \
	.playground.mod.o.cmd .playground.o.cmd modules.order \
	.playground.ko.cmd playground.mod.o playground.o .tmp_versions
