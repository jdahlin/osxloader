AUTOMAKE_OPTIONS = -Wno-portability
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = loader

loader_SOURCES = loader.c loader.h
loader_CFLAGS = -m32
loader_LDFLAGS = -lcap -ldl

test: loader
	./loader true
