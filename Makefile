loader: loader.c macho.h
	gcc -o loader loader.c

clean:
	rm -f loader

.PHONY: clean
