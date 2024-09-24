BUILD_OPTIONS=-DCRYPTO_ENABLED=ON -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
TARGET=build/example/example

all:
	mkdir -p build
	cd build && cmake $(BUILD_OPTIONS)  -S .. -B . -G Ninja 
	cd build && ninja

install:
	cd build && sudo ninja install

clean:
	rm -rf build .cache

check:
	cd example && valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ../$(TARGET)

.PHONY: all clean check 
