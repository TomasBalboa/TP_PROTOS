CC       = gcc
CFLAGS   = -std=c11 -Wall -Werror -Wextra -pedantic -D_POSIX_C_SOURCE=200809L -g -D_GNU_SOURCE $(shell pkg-config --cflags check) -fsanitize=address
LDFLAGS  = -pthread
TST_LIBS = $(shell pkg-config --libs check)