all: clean \
	 build-jre

build-jre: clean-jre
	jlink \
		--add-modules java.base \
		--limit-modules java.base \
		--compress 2 \
		--strip-debug \
		--output ./jre/

clean-jre:
	rm -rf ./jre/

clean: clean-jre
