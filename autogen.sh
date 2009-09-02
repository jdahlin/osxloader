#! /bin/sh

set -e

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

autoreconf -i "$srcdir"

"$srcdir"/configure --enable-maintainer-mode "$@"

