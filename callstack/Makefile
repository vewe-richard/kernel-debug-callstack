obj-m := tracecallstack.o

tracecallstack-objs := callstack.o

myall:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

myclean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f *.o *.ko *.mod.* *.order *.symvers 
