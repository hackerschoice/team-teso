# written by palmers / teso
include ../MakeOpt

OBJECTS = name2add.o Patch.o DevMemPatt.o SymbolTable.o SystemMap.o \
	stoi16.o itos16.o rwKernel.o SymbolFingp.o


all: $(OBJECTS) libs

libs:
	$(AR) $(ARFLAGS) $(AR_OUT) $(OBJECTS)
	$(CXX) $(CXXFLAGS) -shared -o $(SHARE_OUT) $(OBJECTS)

clean:
	rm -rf *.o name2add.c $(SHARE_OUT) $(AR_OUT)

