AUTOMAKE_OPTIONS = -Wno-portability
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = loader

loader_SOURCES = loader.c loader.h
loader_CFLAGS = -m32

test: loader
	./loader true
