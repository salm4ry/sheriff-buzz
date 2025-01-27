CC = gcc
override CFLAGS := -Wall -Wpedantic -fopenmp -std=gnu99
src = $(wildcard *.c)
obj = $(src:.c=)

all: $(obj)
%: %.c
	$(CC) $(CFLAGS) -o $@ $< -lresolv


.PHONY: clean
clean:
	rm -f $(obj)
