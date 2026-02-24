# make -B                 Will build pe-crypt.exe
# make -B -DDEBUG         Will build the debug version of pe-crypt.exe

NAME = PE-Crypt
OBJS = $(NAME).obj
DEF  = $(NAME).def
RES  = $(NAME).res

!if $d(DEBUG)
TASMDEBUG=/zi
LINKDEBUG=/v
!else
TASMDEBUG=
LINKDEBUG=
!endif

!if $d(MAKEDIR)
IMPORT=$(MAKEDIR)\..\lib\import32 aplib.lib
!else
IMPORT=import32
!endif


$(NAME).EXE: $(OBJS) $(DEF)
  @tlink32 /V4.0 /Tpe /aa /c -x $(LINKDEBUG) $(OBJS),$(NAME),, $(IMPORT), $(DEF), $(RES) 
  @del $(OBJS)

.asm.obj:
   @tasm32 $(TASMDEBUG) /ml /m /kh10000 $&.asm
#   @brc32 -r $&.res
