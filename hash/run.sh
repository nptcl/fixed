#!/bin/sh

aout="a.out"
source="../sha.c test.c"
compile="cc -g -Wall -I.. -o ${aout}"

checkerr()
{
  if [ "$?" -ne 0 ]; then
    echo "$@"
    exit 1
  fi
}

rm -f a.out *.o
${compile} ${source}
checkerr "compile"
./${aout}
checkerr "a.out error"

exit 0

