TARGET=build/example/example

all:
	mkdir -p build
	cd build && cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DNDEBUG=1 -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
	cd build && ninja

install:
	cd build && sudo ninja install

run:
	cd example && ../build/example/example
   
test:
	cd build && ctest

clean:
	rm -rf build .cache

check:
	cd example && valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ../$(TARGET)

.PHONY: all clean check 
