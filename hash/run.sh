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

compile_define="-DSHA3_LITTLE_ENDIAN"
#compile_define="-DSHA3_BIG_ENDIAN"

rm -f a.out *.o
${compile} ${compile_define} ${source}
checkerr "compile"
./${aout}
checkerr "a.out error"

exit 0

