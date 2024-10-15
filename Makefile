TARGET=build/example/example

all:
	cd build && cmake ..
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
