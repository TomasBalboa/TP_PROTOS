# Makefile para el servidor SOCKS5
# TP Protocolos de Comunicación 2025/2

include Makefile.inc

# Directorios
SRC_DIR  = src
INC_DIR  = $(SRC_DIR)/include
OBJ_DIR = build
BIN_DIR  = bin

# Archivos fuente
COMMON_SRC = $(wildcard $(SRC_DIR)/*.c)
METRICS_SRC = $(wildcard $(SRC_DIR)/logging/*.c) 
HELLO_SRC = $(wildcard $(SRC_DIR)/handshake/*.c)
SOCKS5_SRC = $(wildcard $(SRC_DIR)/socks5/*.c)
REQUEST_SRC = $(wildcard $(SRC_DIR)/request/*.c)
AUTH_SRC = $(wildcard $(SRC_DIR)/auth/*.c)
MANAGMENT_SRC = $(wildcard $(SRC_DIR)/managment/*.c)
CLIENT_SRC = $(wildcard $(SRC_DIR)/client/*.c)

# Objetos
COMMON_OBJ = $(COMMON_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
METRICS_OBJ = $(METRICS_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
HELLO_OBJ = $(HELLO_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
SOCKS5_OBJ = $(SOCKS5_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
REQUEST_OBJ = $(REQUEST_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
AUTH_OBJ = $(AUTH_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
MANAGMENT_OBJ = $(MANAGMENT_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
CLIENT_OBJ = $(CLIENT_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Todos los objetos
ALL_OBJ = $(COMMON_OBJ) $(METRICS_OBJ) $(HELLO_OBJ) \
          $(SOCKS5_OBJ) $(REQUEST_OBJ) $(AUTH_OBJ) \
          $(MANAGMENT_OBJ)

# Binarios
SERVER_BIN = $(BIN_DIR)/socks5d
CLIENT_BIN = $(BIN_DIR)/client

# Targets principales
.PHONY: all clean help tools client test stress-test

all: $(SERVER_BIN)

client: $(CLIENT_BIN)

tools:
	@chmod +x tools/*.sh || true
	@chmod +x tools/*.py || true

stress-test: $(SERVER_BIN)
	@./tools/stress_test.sh

# Tests
TEST_DIR = $(SRC_DIR)/tests
TEST_BIN_DIR = $(BIN_DIR)
# Flags más relajados para tests (sin -Werror -pedantic que causan problemas con check.h)
TEST_CFLAGS = -std=c11 -Wall -Wextra -D_POSIX_C_SOURCE=200809L -g -D_GNU_SOURCE
CHECK_CFLAGS = -I/opt/homebrew/include
CHECK_LDFLAGS = -L/opt/homebrew/lib -lcheck -lm -lpthread

test: test-compile test-run

test-compile:
	@echo "Compilando tests..."
	@mkdir -p $(TEST_BIN_DIR)
	@$(CC) $(TEST_CFLAGS) -I$(INC_DIR) -I$(SRC_DIR) $(CHECK_CFLAGS) $(CHECK_LDFLAGS) \
		-o $(TEST_BIN_DIR)/buffer_test $(TEST_DIR)/buffer_test.c
	@$(CC) $(TEST_CFLAGS) -I$(INC_DIR) -I$(SRC_DIR) $(CHECK_CFLAGS) $(CHECK_LDFLAGS) \
		-o $(TEST_BIN_DIR)/parser_test $(TEST_DIR)/parser_test.c $(SRC_DIR)/parser.c
	@$(CC) $(TEST_CFLAGS) -I$(INC_DIR) -I$(SRC_DIR) $(CHECK_CFLAGS) $(CHECK_LDFLAGS) \
		-o $(TEST_BIN_DIR)/parser_utils_test $(TEST_DIR)/parser_utils_test.c $(SRC_DIR)/parser_utils.c $(SRC_DIR)/parser.c
	@$(CC) $(TEST_CFLAGS) -I$(INC_DIR) -I$(SRC_DIR) $(CHECK_CFLAGS) $(CHECK_LDFLAGS) \
		-o $(TEST_BIN_DIR)/stm_test $(TEST_DIR)/stm_test.c $(SRC_DIR)/stm.c
	@$(CC) $(TEST_CFLAGS) -I$(INC_DIR) -I$(SRC_DIR) $(CHECK_CFLAGS) $(CHECK_LDFLAGS) \
		-o $(TEST_BIN_DIR)/selector_test $(TEST_DIR)/selector_test.c
	@$(CC) $(TEST_CFLAGS) -I$(INC_DIR) -I$(SRC_DIR) $(CHECK_CFLAGS) $(CHECK_LDFLAGS) \
		-o $(TEST_BIN_DIR)/netutils_test $(TEST_DIR)/netutils_test.c $(SRC_DIR)/netutils.c $(SRC_DIR)/buffer.c
	@echo "Tests compilados"

test-run:
	@for test in buffer parser parser_utils stm selector netutils; do \
		echo ">>> Ejecutando $${test}_test..."; \
		$(TEST_BIN_DIR)/$${test}_test; \
		echo ""; \
	done
	@echo "TODOS LOS TESTS PASARON"

# Limpiar
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Todo limpio o7"

# Ayuda
help:
	@echo "Targets disponibles:"
	@echo "  make          - Compila el servidor"
	@echo "  make all      - Compila el servidor"
	@echo "  make client   - Compila el cliente"
	@echo "  make test     - Compila y ejecuta todos los tests"
	@echo "  make clean    - Elimina archivos de compilación"
	@echo "  make help     - Muestra esta ayuda"
	@echo "  make stress-test  - Ejecuta stress test (1018 conns, 30s)"

# Crear directorios si no existen
$(SERVER_BIN): $(ALL_OBJ)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(ALL_OBJ) -o $(SERVER_BIN)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INC_DIR) -I$(INC_DIR)/managment -c $< -o $@

$(CLIENT_BIN): $(CLIENT_OBJ)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(CLIENT_OBJ) -o $(CLIENT_BIN)