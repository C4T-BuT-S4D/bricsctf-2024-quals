all:
	gcc -fno-stack-protector main.c -o escape
	patchelf --set-rpath './' escape
	sudo chmod u+s ./escape
