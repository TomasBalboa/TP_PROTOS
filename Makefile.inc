CC       = gcc

# Compilación condicional según BUILD
ifeq ($(BUILD),debug)
    CFLAGS   = -std=c11 -Wall -Werror -Wextra -pedantic -D_POSIX_C_SOURCE=200809L -g -D_GNU_SOURCE -DDEBUG_MODE $(shell pkg-config --cflags check)
else
    CFLAGS   = -std=c11 -Wall -Werror -Wextra -pedantic -D_POSIX_C_SOURCE=200809L -g -D_GNU_SOURCE $(shell pkg-config --cflags check)
endif

LDFLAGS  = -pthread
TST_LIBS = $(shell pkg-config --libs check)