all:
	cd build && cmake .. && make
	echo "Running example in folder $(shell pwd)/"
	cd example && ../build/example/example

clean:
	rm -rf build .cache

check:
	cd example && \
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ../build/example/example

.PHONY: all clean check
