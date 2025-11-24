

# Configuración del compilador
CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -g3 -O2 -D_POSIX_C_SOURCE=200809L
LDFLAGS = 

# Directorios
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
BIN_DIR = bin

# Core modules (tu implementación existente)
CORE_SOURCES = $(SRC_DIR)/buffer.c $(SRC_DIR)/selector.c $(SRC_DIR)/stm.c \
               $(SRC_DIR)/netutils.c $(SRC_DIR)/parser.c $(SRC_DIR)/parser_utils.c

# Archivos fuente principales
SERVER_SOURCES = $(SRC_DIR)/server/main.c args.c $(CORE_SOURCES)
ADMIN_CLIENT_SOURCES = $(wildcard $(SRC_DIR)/client/*.c) args.c $(CORE_SOURCES)

# Tests
TEST_SOURCES = $(SRC_DIR)/buffer_test.c $(SRC_DIR)/selector_test.c $(SRC_DIR)/stm_test.c \
               $(SRC_DIR)/netutils_test.c $(SRC_DIR)/parser_test.c $(SRC_DIR)/parser_utils_test.c

# Objetos
SERVER_OBJECTS = $(SERVER_SOURCES:.c=.o)
ADMIN_CLIENT_OBJECTS = $(ADMIN_CLIENT_SOURCES:.c=.o)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o) $(CORE_SOURCES:.c=.o)

# Ejecutables
SERVER_TARGET = socks5d
ADMIN_CLIENT_TARGET = socks5-admin
TEST_TARGET = run_tests

# Targets principales
.PHONY: all clean server client test debug install info

all: server

server: $(SERVER_TARGET)

client: $(ADMIN_CLIENT_TARGET)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Compilación del servidor
$(SERVER_TARGET): $(SERVER_OBJECTS)
	$(CC) $(SERVER_OBJECTS) $(LDFLAGS) -o $@

# Compilación del cliente administrativo  
$(ADMIN_CLIENT_TARGET): $(ADMIN_CLIENT_OBJECTS)
	$(CC) $(ADMIN_CLIENT_OBJECTS) $(LDFLAGS) -o $@

# Compilación de tests
$(TEST_TARGET): $(TEST_OBJECTS)
	$(CC) $(TEST_OBJECTS) $(LDFLAGS) -o $@

# Compilación de objetos
%.o: %.c
	$(CC) $(CFLAGS) -I. -I$(INCLUDE_DIR) -c $< -o $@

# Limpieza
clean:
	rm -f *.o $(SRC_DIR)/*.o $(SRC_DIR)/server/*.o
	rm -f $(SERVER_TARGET) $(ADMIN_CLIENT_TARGET) $(TEST_TARGET)

# Testing individual de módulos
test-buffer: $(SRC_DIR)/buffer_test.c $(SRC_DIR)/buffer.c
	$(CC) $(CFLAGS) -I. $^ -o test-buffer && ./test-buffer

test-selector: $(SRC_DIR)/selector_test.c $(SRC_DIR)/selector.c
	$(CC) $(CFLAGS) -I. $^ -o test-selector && ./test-selector

test-stm: $(SRC_DIR)/stm_test.c $(SRC_DIR)/stm.c  
	$(CC) $(CFLAGS) -I. $^ -o test-stm && ./test-stm

test-netutils: $(SRC_DIR)/netutils_test.c $(SRC_DIR)/netutils.c $(SRC_DIR)/buffer.c
	$(CC) $(CFLAGS) -I. $^ -o test-netutils && ./test-netutils

test-parser: $(SRC_DIR)/parser_test.c $(SRC_DIR)/parser.c $(SRC_DIR)/parser_utils.c $(SRC_DIR)/buffer.c
	$(CC) $(CFLAGS) -I. $^ -o test-parser && ./test-parser

# Debug targets
debug: CFLAGS += -DDEBUG -fsanitize=address -fsanitize=undefined
debug: all

# Valgrind testing
valgrind: server
	valgrind --leak-check=full --show-leak-kinds=all ./$(SERVER_TARGET) --help

# Información del build
info:
	@echo "Compiler: $(CC)"
	@echo "Flags: $(CFLAGS)"
	@echo "Server sources: $(SERVER_SOURCES)"
	@echo "Core modules: $(CORE_SOURCES)"
	@echo "Test sources: $(TEST_SOURCES)"
