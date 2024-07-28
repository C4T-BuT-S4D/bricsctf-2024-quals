all: clean \
	 compile-jre \
	 compile-dollyclass \
	 compile-dolly \
	 patch

patch: clean-patch
	echo please, do it manually! && false

	# find Dolly.class patch
	test -f ./Dolly.class || cp ../dollyclass/Dolly.class ./Dolly.class
	test -f ./libchecker.so || cp ../dollyclass/libchecker.so ./libchecker.so
	python3 patch.py DOLLYCLASS

	# patch dolly
	test -f dolly.bak && mv dolly.bak dolly || true
	python3 patch.py DOLLY
	mv dolly dolly.bak

	mv dolly.patched dolly
	chmod +x dolly

	strip --strip-debug dolly

clean-patch:
	rm -f dolly.patched

compile-dolly: clean-dolly
	g++ -std=c++17 -O0 \
		-pie -fPIE \
		libjava_array.o libverify_array.o libjimage_array.o libnet_array.o libnio_array.o libzip_array.o modules_array.o libjvm_array.o \
		dollyclass_array.o \
		main.cpp dropper.cpp dolly.cpp \
		-I../jre/include/ \
		-I../jre/include/linux/ \
		-static-libstdc++ \
		-static-libgcc \
		-Wl,-z,relro,-z,lazy \
		-ldl -lstdc++fs \
		-o dolly

clean-dolly:
	rm -f dolly

compile-jre: clean-jre
	test -d ../jre/

	python3 generate.py JRE

	gcc -c libjava_array.c -Os
	gcc -c libverify_array.c -Os
	gcc -c libjimage_array.c -Os
	gcc -c libnet_array.c -Os
	gcc -c libnio_array.c -Os
	gcc -c libzip_array.c -Os
	gcc -c modules_array.c -Os
	gcc -c libjvm_array.c -Os

clean-jre:
	rm -f \
		libjava_array.c libjava_array.o \
		libverify_array.c libverify_array.o \
		libjimage_array.c libjimage_array.o \
		libnet_array.c libnet_array.o \
		libnio_array.c libnio_array.o \
		libzip_array.c libzip_array.o \
		modules_array.c modules_array.o \
		libjvm_array.c libjvm_array.o

compile-dollyclass: clean-dollyclass
	test -f ./Dolly.class || cp ../dollyclass/Dolly.class ./Dolly.class
	python3 generate.py DOLLYCLASS
	gcc -c dollyclass_array.c -Os

clean-dollyclass:
	rm -f dollyclass_array.c dollyclass_array.o

clean: clean-patch clean-dolly clean-jre clean-dollyclass
	rm -f Dolly.class libchecker.so
