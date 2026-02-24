#!/bin/bash
# script to find system call table in /dev/mem
# written by palmers / teso

TMP=./______some_strange_tmp_file

A=`./findsym -s sys_exit`
B=`./findsym -s sys_fork`
C=`./findsym -s sys_read`
D=`./findsym -s sys_write`

#echo $A $B $C $D
#transform the addresses ...
A1=`echo $A | cut -c 7,8`
A2=`echo $A | cut -c 5,6`
A3=`echo $A | cut -c 3,4`
A4=`echo $A | cut -c 1,2`

B1=`echo $B | cut -c 7,8`
B2=`echo $B | cut -c 5,6`
B3=`echo $B | cut -c 3,4`
B4=`echo $B | cut -c 1,2`

C1=`echo $C | cut -c 7,8`
C2=`echo $C | cut -c 5,6`
C3=`echo $C | cut -c 3,4`
C4=`echo $C | cut -c 1,2`

D1=`echo $D | cut -c 7,8`
D2=`echo $D | cut -c 5,6`
D3=`echo $D | cut -c 3,4`
D4=`echo $D | cut -c 1,2`

echo "sys_call_table c01a0000 c0260000 -4 10 $A1 $A2 $A3 $A4 $B1 $B2 $B3 $B4 $C1 $C2 $C3 $C4 $D1 $D2 $D3 $D4" > $TMP
./findsym -f $TMP sys_call_table
rm $TMP
