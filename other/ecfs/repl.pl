#!/usr/bin/perl

# Written to transform ext2 functions and structs
# to ecfs.
#

my $f= shift;
open I, "<$f" or die "$!";
open O, ">$f.new" or die "$!";

while (<I>) {
	s/ext2/ecfs/g;
	s/EXT2/ECFS/g;

	s/const// if (/ecfs_free_blocks/);
	s/const// if (/ecfs_new_block/);

	print O;
}

close O;
close I;

		
unlink $f;
rename "$f.new", $f;
