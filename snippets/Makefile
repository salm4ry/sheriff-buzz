CC = gcc
override CFLAGS := -Wall -Wpedantic -std=gnu99 -ggdb
src = $(wildcard *.c)
obj = $(src:.c=)

all: $(obj)
%: %.c
	$(CC) $(CFLAGS) -o $@ $< -lresolv


.PHONY: clean
clean:
	rm -f $(obj)
