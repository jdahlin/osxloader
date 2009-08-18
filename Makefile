loader: loader.c macho.h
	gcc -o loader loader.c

test: loader
	./loader true

clean:
	rm -f loader

.PHONY: clean
