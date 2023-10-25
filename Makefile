CFLAGS=-Wall -Werror -pedantic -O3 -Wno-unused-function

all: select epoll

select:
	$(CC) $(CFLAGS) main.c -O3 server.c str.c threadpool.c -o select-server -lpthread

epoll:
	$(CC) $(CFLAGS) epoll.c -ggdb -o epoll-server

test:
	$(CC) $(CFLAGS) str.c str_test.c && ./a.out && rm -f ./a.out

clean:
	rm -f select-server epoll-server a.out