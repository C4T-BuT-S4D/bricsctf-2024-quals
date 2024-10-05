obj-m += physler.o
KVERSION = 6.11.1
#ccflags-y := -O0

all:
	make -C /root/dev/brics-2024/pwn/kernel-build/dev/linux-6.11.1 M=$(PWD) modules
clean:
	make -C /root/dev/brics-2024/pwn/kernel-build/dev/linux-6.11.1 M=$(PWD) clean
