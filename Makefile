TARGET=build/example/example

all:
	mkdir -p build
	cd build && cmake -G Ninja \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..

	cd build && ninja

install:
	cd build && sudo ninja install

# Code generation
# Generate arrays used by the projects
INCLUDES := $$'\#include <solidc/cstr.h>\n\ntypedef struct {cstr*name; cstr*value;} header_t;'

generate:
	arraygen -name kv -type header_t -stack false \
	-i $(INCLUDES)\
	| clang-format > include/kv.h

run:
	cd example && ../build/example/example
   
test:
	cd build && ctest

clean:
	rm -rf build .cache

check:
	cd example && valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ../$(TARGET)

.PHONY: all clean check 
