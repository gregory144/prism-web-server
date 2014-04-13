#!/bin/sh

cd `dirname "$0"`

if [ "$LIBTOOLIZE" = "" ] && [ "`uname`" = "Darwin" ]; then
LIBTOOLIZE=glibtoolize
fi

ACLOCAL=${ACLOCAL:-aclocal}
AUTOCONF=${AUTOCONF:-autoconf}
AUTOMAKE=${AUTOMAKE:-automake}
AUTOHEADER=${AUTOHEADER:-autoheader}
LIBTOOLIZE=${LIBTOOLIZE:-libtoolize}

set -ex
"$LIBTOOLIZE"
"$ACLOCAL" -I m4
"$AUTOCONF"
"$AUTOHEADER"
"$AUTOMAKE" --add-missing --copy
