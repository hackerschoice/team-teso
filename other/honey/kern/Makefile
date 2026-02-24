SRCS = honey.c
SRCS += vnode_if.h
CFLAGS = -I../
KMOD = honey

.include <bsd.kmod.mk>

reload: all unload load
