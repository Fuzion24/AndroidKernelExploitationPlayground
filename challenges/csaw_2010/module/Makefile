obj-y += csaw.o


#CROSS_COMPILE=$(AOSP_ROOT)/prebuilts/gcc/linux-x86/arm/arm-eabi-4.7/bin/arm-eabi-
#KERNEL_DIR = ../msm

all:
	make -C $(KERNEL_DIR) M=$(PWD)/ ARCH=arm CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
