# Makefile para el servidor SOCKS5
# TP Protocolos de Comunicación 2025/2

include Makefile.inc

# Directorios
SRC_DIR  = src
INC_DIR  = $(SRC_DIR)/include
OBJ_DIR = build
BIN_DIR  = bin

# Archivos fuente

tools: 
	@chmod +x tools/*.sh || true
	@chmod +x tools/*.py || true

COMMON_SRC = $(wildcard $(SRC_DIR)/*.c)
METRICS_SRC = $(wildcard $(SRC_DIR)/logging/*.c) 
HELLO_SRC = $(wildcard $(SRC_DIR)/handshake/*.c)
SOCKS5_SRC = $(wildcard $(SRC_DIR)/socks5/*.c)
REQUEST_SRC = $(wildcard $(SRC_DIR)/request/*.c)
AUTH_SRC = $(wildcard $(SRC_DIR)/auth/*.c)
ARGS_SRC = args.c
MANAGEMENT_SRC = $(wildcard $(SRC_DIR)/managment/*.c)

# Objetos
COMMON_OBJ = $(COMMON_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
METRICS_OBJ = $(METRICS_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
HELLO_OBJ = $(HELLO_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
SOCKS5_OBJ = $(SOCKS5_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
REQUEST_OBJ = $(REQUEST_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
AUTH_OBJ = $(AUTH_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
ARGS_OBJ = $(OBJ_DIR)/args.o
MANAGEMENT_OBJ = $(MANAGEMENT_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Todos los objetos
ALL_OBJ = $(COMMON_OBJ) $(METRICS_OBJ) $(HELLO_OBJ) $(SOCKS5_OBJ) $(REQUEST_OBJ) $(AUTH_OBJ) $(ARGS_OBJ) $(MANAGEMENT_OBJ)

# Binarios
SERVER_BIN = $(BIN_DIR)/socks5d

# Targets principales
.PHONY: all clean help tools

all: $(SERVER_BIN)

# Limpiar
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Todo limpio o7"

# Ayuda
help:
	@echo "Targets disponibles:"
	@echo "  make          - Compila el servidor"
	@echo "  make all      - Compila el servidor"
	@echo "  make clean    - Elimina archivos de compilación"
	@echo "  make help     - Muestra esta ayuda"

# Crear directorios si no existen
$(SERVER_BIN): $(ALL_OBJ)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(ALL_OBJ) -o $(SERVER_BIN)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

# Regla especial para args.o (está en la raíz del proyecto)
$(OBJ_DIR)/args.o: args.c args.h
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@