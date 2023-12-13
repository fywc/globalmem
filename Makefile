ifneq ($(KERNELRELEASE),)
	obj-m := globalmem.o
#	obj-m += remap_pfn_vmalloc.o
#	obj-m += remap_pfn_alloc_pages.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR)  M=$(PWD) modules

clean:
	@rm -rf *.o *.mod.c *.mod.o *.ko *.order *.symvers .*.cmd .tmp_versions
endif
