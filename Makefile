CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -O2 -pthread
LDFLAGS = -pthread

SRC_DIR = src
OBJ_DIR = build
TARGET = c-port-scanner

SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/scanner.c
OBJS = $(OBJ_DIR)/main.o $(OBJ_DIR)/scanner.o

.PHONY: all clean valgrind

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(SRC_DIR)/scanner.h
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all --track-fds=yes ./$(TARGET) -t 127.0.0.1 -s 1 -e 100 -T 10

clean:
	rm -rf $(OBJ_DIR) $(TARGET)
