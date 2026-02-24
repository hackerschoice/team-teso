#!/bin/bash


OBJOBF_VERSION=0$(./objobf 2>&1 | grep " version " | cut -d '0' -f2- | cut -d '.' -f-3)
echo $OBJOBF_VERSION

mkdir -p alpha-releases/objobf-$OBJOBF_VERSION/doc
mkdir -p alpha-releases/objobf-$OBJOBF_VERSION/example
cp doc/objobf.1 doc/objobf-CHANGES doc/objobf-README \
	alpha-releases/objobf-$OBJOBF_VERSION/doc/
cp testcases/quicksort.c testcases/main.c testcases/2-obf/reducebind.c \
	alpha-releases/objobf-$OBJOBF_VERSION/example/
cp objobf alpha-releases/objobf-$OBJOBF_VERSION-nostripped
strip objobf
util/sstrip objobf
cp objobf alpha-releases/objobf-$OBJOBF_VERSION/
cd alpha-releases/objobf-$OBJOBF_VERSION/
ln -s doc/objobf-README README

cd ..
tar cfvj objobf-$OBJOBF_VERSION.tar.bz2 objobf-$OBJOBF_VERSION


