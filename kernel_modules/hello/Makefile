ifneq ($(KERNELRELEASE),)
	obj-m := hello.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf *.o *~ .depend *.cmd *.ko *.mod.c .tmp_versions modules.order Module.symvers hello.ko.unsigned

.PHONY: modules modules_install clean
endif
