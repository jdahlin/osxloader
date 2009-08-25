loader: loader.c macho.h
	gcc -m32 -o loader loader.c

test: loader
	./loader true

clean:
	rm -f loader

.PHONY: clean
