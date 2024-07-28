all: clean \
	 compile-dollyclass

compile-dollyclass: clean-dollyclass
	test -f ./libchecker.so || cp ../libchecker/libchecker.so ./libchecker.so
	mv Dolly.java Dolly.template.java
	python3 generate.py
	javac -J-Xms8G -J-Xmx8G Dolly.java
	mv Dolly.template.java Dolly.java

clean-dollyclass:
	rm -f Dolly.class

clean: clean-dollyclass
	rm -f libchecker.so
