#!/bin/sh

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
	make clean
	make compile_define="-D${define1}=1 -D${define2}=1"
	checkerr "compile"
	./a.out
	checkerr "a.out error"
}

test_fixed "DEBUG"   "8bit"   "FIXED_DEBUG" "FIXED_8BIT"
test_fixed "DEBUG"   "16bit"  "FIXED_DEBUG" "FIXED_16BIT"
test_fixed "DEBUG"   "32bit"  "FIXED_DEBUG" "FIXED_32BIT"
test_fixed "DEBUG"   "64bit"  "FIXED_DEBUG" "FIXED_64BIT"

test_fixed "RELEASE" "8bit"   "FIXED_RELEASE" "FIXED_8BIT"
test_fixed "RELEASE" "16bit"  "FIXED_RELEASE" "FIXED_16BIT"
test_fixed "RELEASE" "32bit"  "FIXED_RELEASE" "FIXED_32BIT"
test_fixed "RELEASE" "64bit"  "FIXED_RELEASE" "FIXED_64BIT"

exit 0

