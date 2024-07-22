#!/bin/sh

# md5
echo "md5"
for i in `cat key`; do
  hash=`echo -n "$i" | md5sum --quiet`
  echo "$i $hash"
done > hash.md5


# sha1
echo "sha1"
for i in `cat key`; do
  hash=`echo -n "$i" | sha1sum --quiet`
  echo "$i $hash"
done > hash.sha1


# sha256
echo "sha256"
for i in `cat key`; do
  hash=`echo -n "$i" | sha256sum --quiet`
  echo "$i $hash"
done > hash.sha256


# sha384
echo "sha384"
for i in `cat key`; do
  hash=`echo -n "$i" | sha384sum --quiet`
  echo "$i $hash"
done > hash.sha384


# sha512
echo "sha512"
for i in `cat key`; do
  hash=`echo -n "$i" | sha512sum --quiet`
  echo "$i $hash"
done > hash.sha512


# sha3-256
echo "sha3-256"
for i in `cat key`; do
  hash=`echo -n "$i" | openssl dgst -sha3-256 | awk '{print $2}'`
  echo "$i $hash"
done > hash.sha3-256


# sha3-512
echo "sha3-512"
for i in `cat key`; do
  hash=`echo -n "$i" | openssl dgst -sha3-512 | awk '{print $2}'`
  echo "$i $hash"
done > hash.sha3-512


# shake-256-256
echo "shake-256-256"
for i in `cat key`; do
  hash=`echo -n "$i" | openssl dgst -shake-256 -xoflen=32 | awk '{print $2}'`
  echo "$i $hash"
done > hash.shake-256-256


# shake-256-800
echo "shake-256-800"
for i in `cat key`; do
  hash=`echo -n "$i" | openssl dgst -shake-256 -xoflen=100 | awk '{print $2}'`
  echo "$i $hash"
done > hash.shake-256-800


echo OK
exit 0

