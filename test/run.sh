#!/bin/sh

aout="a.out"
source="../fixed.c ../crypt.c test.c"
compile="cc -g -Wall -I.. -o ${aout}"

checkerr()
{
  if [ "$?" -ne 0 ]; then
    echo "$@"
    exit 1
  fi
}

test_fixed()
{
	local x="$1"
	local y="$2"
	local define1="$3"
	local define2="$4"

	echo "Test: ${x} + ${y}"
	rm -f a.out *.o
	${compile} ${define1} ${define2} ${source}
	checkerr "compile"
	./${aout}
	checkerr "a.out error"
}

test_fixed "DEBUG"   "8bit"   "-DFIXED_DEBUG" "-DFIXED_8BIT"
test_fixed "DEBUG"   "16bit"  "-DFIXED_DEBUG" "-DFIXED_16BIT"
test_fixed "DEBUG"   "32bit"  "-DFIXED_DEBUG" "-DFIXED_32BIT"
test_fixed "DEBUG"   "64bit"  "-DFIXED_DEBUG" "-DFIXED_64BIT"

test_fixed "RELEASE" "8bit"   "-DFIXED_RELEASE" "-DFIXED_8BIT"
test_fixed "RELEASE" "16bit"  "-DFIXED_RELEASE" "-DFIXED_16BIT"
test_fixed "RELEASE" "32bit"  "-DFIXED_RELEASE" "-DFIXED_32BIT"
test_fixed "RELEASE" "64bit"  "-DFIXED_RELEASE" "-DFIXED_64BIT"

exit 0

