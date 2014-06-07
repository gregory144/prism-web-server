SUBDIRS = src .

CC = clang
ACLOCAL_AMFLAGS = -I m4

style:
	astyle --options=astyle.cfg -r "src/*.c" "src/*.h"
