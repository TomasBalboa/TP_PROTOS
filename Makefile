# Makefile para el servidor SOCKS5
# TP Protocolos de Comunicación 2025/2

CC       = gcc
CFLAGS   = -std=c11 -Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200809L -g
LDFLAGS  = -pthread

# Directorios
SRC_DIR  = src
INC_DIR  = $(SRC_DIR)/include
BUILD_DIR = build
BIN_DIR  = bin

# Archivos fuente
COMMON_SRC = $(SRC_DIR)/buffer.c \
             $(SRC_DIR)/selector.c \
             $(SRC_DIR)/parser.c \
             $(SRC_DIR)/parser_utils.c \
             $(SRC_DIR)/stm.c \
             $(SRC_DIR)/netutils.c

SOCKS5_SRC = $(SRC_DIR)/handshake/hello.c \
             $(SRC_DIR)/request/request.c \
             $(SRC_DIR)/copy.c \
             $(SRC_DIR)/socks5/socks5nio.c

SERVER_SRC = $(SRC_DIR)/main.c \
             args.c \
             $(COMMON_SRC) \
             $(SOCKS5_SRC)

# Objetos
SERVER_OBJ = $(SERVER_SRC:%.c=$(BUILD_DIR)/%.o)

# Binarios
SERVER_BIN = $(BIN_DIR)/socks5d

# Targets principales
.PHONY: all clean server test

all: server

server: $(SERVER_BIN)

# Crear directorios si no existen
$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@

$(BUILD_DIR)/src $(BUILD_DIR)/src/socks5:
	mkdir -p $@

# Compilar servidor
$(SERVER_BIN): $(SERVER_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ Servidor compilado: $@"

# Regla genérica para objetos
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR) $(BUILD_DIR)/src $(BUILD_DIR)/src/socks5
	$(CC) $(CFLAGS) -I$(INC_DIR) -I$(SRC_DIR)/socks5 -c $< -o $@

# Limpiar
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "✓ Archivos de compilación eliminados"

# Tests (para más adelante)
test:
	@echo "Tests no implementados aún"

# Ayuda
help:
	@echo "Targets disponibles:"
	@echo "  make          - Compila el servidor"
	@echo "  make server   - Compila el servidor"
	@echo "  make clean    - Elimina archivos de compilación"
	@echo "  make test     - Ejecuta tests (TODO)"
	@echo "  make help     - Muestra esta ayuda"
