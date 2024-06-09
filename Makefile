CC=gcc
CFLAGS=-Wall -Werror -Wextra -pedantic -ggdb -DMAX_DIRNAME=255
LDFLAGS=-lcurl -lmagic -lpcre2-8 -lm -lsolidc
SRC_DIR=http
OBJ_DIR=obj
SRCS=$(wildcard $(SRC_DIR)/*.c) main.c
OBJS=$(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
TARGET=server

all: $(TARGET)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

check: all
	valgrind -s --leak-check=full --track-origins=yes --show-leak-kinds=all ./$(TARGET) 8080

# Install dependencies
dep:
	sudo apt-get install libcurl4-openssl-dev libmagic-dev libpcre3 libpcre3-dev

clean:
	rm -f $(OBJ_DIR)/*.o $(TARGET)

.PHONY: all clean
