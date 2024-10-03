all:
	rm -f third_party/*

	wget https://raw.githubusercontent.com/yhirose/cpp-httplib/refs/tags/v0.18.0/httplib.h -O third_party/httplib.h
	wget https://raw.githubusercontent.com/nlohmann/json/refs/tags/v3.11.3/single_include/nlohmann/json.hpp -O third_party/json.h
	wget https://raw.githubusercontent.com/B-Con/crypto-algorithms/cfbde48414baacf51fc7c74f275190881f037d32/sha256.h -O third_party/sha256.h
	wget https://raw.githubusercontent.com/B-Con/crypto-algorithms/cfbde48414baacf51fc7c74f275190881f037d32/sha256.c -O third_party/sha256.cpp

	g++-12 \
		-std=c++20 -O2 \
		-I. \
		main.cpp models/*.cpp server/*.cpp services/*.cpp storage/*.cpp third_party/*.cpp utils/*.cpp \
		-lsqlite3 \
		-o excess
