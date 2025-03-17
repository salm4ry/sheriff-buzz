in = $(wildcard *.roff)
out = $(in:.roff=.man)

all: $(out)
%.man: %.roff
	groff -Tascii -man $< > $@

.PHONY: less
less:
	less $(out)

.PHONY: clean
clean:
	rm -f $(out)
