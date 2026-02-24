#!/bin/sh
# written by palmers / teso
# generates SymbolFind.conf
# --> unfinished!
MAP=../2.2.x/System.map-ditchen-2.2.16

for x in kmalloc sys_execve sys_unlink sys_chmod sys_kill sys_exit sys_fork sys_read sys_write sys_open sys_close init sys_setuid sys_setgid sys_getdents sys_socketcall; do
ADD=`grep \ $x\$ $MAP | awk '{print $1}' -`
PATT=`./readsym d $ADD f`
echo $x "	 " $ADD " 00 0f" $PATT
done
