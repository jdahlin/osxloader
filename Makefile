loader: loader.c macho.h
	gcc -ldl -g -Wall -m32 -o loader loader.c

test: loader
	./loader true

clean:
	rm -f loader

.PHONY: clean
