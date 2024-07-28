all: clean \
	 download-ffi compile-libffi \
	 download-zlib compile-libz \
	 download-python compile-libpython \
	 build-program build-runtime \
	 compile-libdolly compile-atexit compile-libchecker

compile-atexit: clean-atexit
	./Python-3.10.1/python -c "import hijacked" || true
	mv ./__pycache__/hijacked.cpython-310.pyc hijacked.pyc
	rm -rf ./__pycache__/
	python3 generate.py ATEXIT
	mv atexit.c ./Python-3.10.1/Modules/atexitmodule.c
	
	gcc -O0 -Os \
		-c \
		-static -fPIC \
		-masm=intel \
		-fvisibility=hidden \
		-DPy_BUILD_CORE_MODULE -DNDEBUG \
		./Python-3.10.1/Modules/atexitmodule.c \
		-I./Python-3.10.1/ \
		-I./Python-3.10.1/Include/ \
		-I./Python-3.10.1/Include/internal/ \
		-o ./Python-3.10.1/Modules/atexitmodule.o

clean-atexit:
	rm -f hijacked.pyc

compile-libdolly: clean-libdolly
	gcc -O0 \
		-c \
		libdolly.c \
		-I../jre/include/ \
		-I../jre/include/linux/

clean-libdolly:
	rm -f libdolly.o

compile-libchecker: clean-libchecker
	# build libpython3.10.a
	cd ./Python-3.10.1/ \
		&& rm -f libpython3.10.a \
		&& ar rcs libpython3.10.a ./Modules/*.o ./Objects/*.o ./Python/*.o ./Parser/*.o ./Modules/_ctypes/*.o

	gcc -O0 \
		-shared -fPIC \
		libchecker.c \
		libdolly.o program.o runtime.o \
		-I./Python-3.10.1/ \
		-I./Python-3.10.1/Include/ \
		-I./Python-3.10.1/Include/internal/ \
		-I./Python-3.10.1/Modules/ \
		-I./Python-3.10.1/Modules/_ctypes/ \
		-I./Python-3.10.1/Objects/ \
		-I./Python-3.10.1/Python/ \
		-L./libffi-3.4.6/ -l:libffi.a \
		-L./zlib-1.3.1/ -l:libz.a \
		-L./Python-3.10.1/ -l:libpython3.10.a \
		-lm -lffi -lz \
		-o libchecker.so

	strip --strip-debug ./libchecker.so

	strip -N my_marshal_loads ./libchecker.so
	strip -N hook_marshal_loads ./libchecker.so
	strip -N Hijacked ./libchecker.so
	strip -N HijackedLength ./libchecker.so

clean-libchecker:
	rm -f libchecker.so

build-program: clean-program
	python3 generate.py CHECK
	./Python-3.10.1/python -c "import check" || true
	mv ./__pycache__/check.cpython-310.pyc check.pyc
	rm -rf ./__pycache__/
	python3 generate.py PROGRAM
	gcc -c program.c -Os

clean-program:
	rm -f check.py check.pyc program.c program.o

build-runtime: clean-runtime
	mkdir ./bundle/
	cp -R ./Python-3.10.1/Lib/* ./bundle/
	cd ./bundle/ \
		&& rm -rf ./test/ ./tkinter/ ./__pycache__/ \
		&& zip -r -9 runtime.zip . \
		&& mv runtime.zip ..
	python3 generate.py RUNTIME
	gcc -c runtime.c -Os

clean-runtime:
	rm -rf ./bundle/
	rm -f runtime.zip runtime.c runtime.o

download-ffi: clean-ffi
	wget https://github.com/libffi/libffi/releases/download/v3.4.6/libffi-3.4.6.tar.gz
	tar -xzvf libffi-3.4.6.tar.gz
	rm -f libffi-3.4.6.tar.gz

clean-ffi:
	rm -rf ./libffi-3.4.6/

compile-libffi:
	cd ./libffi-3.4.6/ \
		&& ./configure \
		&& make \
		&& mv ./x86_64-pc-linux-gnu/.libs/libffi.a libffi.a \
		&& mv ./x86_64-pc-linux-gnu/include/*.h include/ \
		&& mv ./x86_64-pc-linux-gnu/*.h include/

download-zlib: clean-zlib
	wget https://www.zlib.net/zlib131.zip
	unzip zlib131.zip
	rm -f zlib131.zip

clean-zlib:
	rm -rf ./zlib-1.3.1/

compile-libz:
	cd ./zlib-1.3.1/ \
		&& ./configure --static \
		&& make CFLAGS="-fPIC -shared" \
		&& make install

download-python: clean-python
	wget https://www.python.org/ftp/python/3.10.1/Python-3.10.1.tgz
	tar -xzvf Python-3.10.1.tgz
	rm -f Python-3.10.1.tgz

clean-python:
	rm -rf ./Python-3.10.1/

compile-libpython:
	# remove unused modules
	for module in test bz2 ssl sqlite curses uuid blake2 lzma sha3 crypt tkinter expat; do \
		echo $$module ; \
		find ./Python-3.10.1/ -type f | grep $$module | xargs rm -f ; \
	done

	cd ./Python-3.10.1 \
		&& ./configure LDFLAGS="-static -fPIC -O0 -Os" CFLAGS="-static -fPIC -O0 -Os" --with-static-libpython

	# add zlib, _ctypes, _struct into config
	patch -i config.patch ./Python-3.10.1/Modules/config.c

	cd ./Python-3.10.1/ \
		&& make LDFLAGS="-static -fPIC -O0 -Os" CFLAGS="-static -fPIC -O0 -Os" \
		|| true

	for file in ./Python-3.10.1/Modules/_struct.c ./Python-3.10.1/Modules/zlibmodule.c `find ./Python-3.10.1/Modules/_ctypes/ -type f | grep '\.c$$'`; do \
		echo $$file; \
		gcc -std=c99 -O0 -Os \
			-c \
			-static -fPIC \
			$$file \
			-DNDEBUG -DPy_BUILD_CORE -DPLATLIBDIR -DPy_BUILD_CORE_BUILTIN \
			-fvisibility=hidden \
			-I./Python-3.10.1/Parser/ \
			-I./Python-3.10.1/Include/internal \
			-I./Python-3.10.1/Python/clinic \
			-I./Python-3.10.1/Python \
			-I./Python-3.10.1/Include \
			-I./Python-3.10.1/ \
			-I./libffi-3.4.6/include \
			-I./zlib-1.3.1/include \
			-L./libffi-3.4.6/ -l:libffi.a \
			-L./zlib-1.3.1/ -l:libz.a \
			-lffi -lz -lm \
			-o $$file.o \
		; \
		true; \
	done

	# conflict with libffi
	rm -f ./Python-3.10.1/Modules/_ctypes/malloc_closure.c.o

	cd ./Python-3.10.1/ \
		&& rm -f libpython3.10.a \
		&& ar rcs libpython3.10.a ./Modules/*.o ./Objects/*.o ./Python/*.o ./Parser/*.o ./Modules/_ctypes/*.o

	cd ./Python-3.10.1/ \
		&& gcc ./Programs/python.o ./libpython3.10.a -o ./python \
			-I./../libffi-3.4.6/include \
			-I./../zlib-1.3.1/include \
			-L./../libffi-3.4.6/ -l:libffi.a \
			-L./../zlib-1.3.1/ -l:libz.a \
			-lm -lpthread -ldl -lutil

	# patch atexitmodule to modify it later
	patch -i atexit.patch -o atexit.template.c ./Python-3.10.1/Modules/atexitmodule.c

clean: clean-atexit clean-libchecker clean-libdolly clean-program clean-runtime clean-zlib clean-python clean-ffi
	rm -f atexit.template.c
