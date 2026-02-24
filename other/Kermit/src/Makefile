# written by palmers / teso
include ../MakeOpt

all: load unload findsym readsym writesym callsyscall

load:
	$(CXX) $(CXXFLAGS) load.cpp -o $(BIN_DIR)/load $(AR_OUT)

unload:
	$(CXX) $(CXXFLAGS) unload.cpp -o $(BIN_DIR)/unload $(AR_OUT)

readsym:
	$(CXX) $(CXXFLAGS) readsym.cpp -o $(BIN_DIR)/readsym $(AR_OUT)

writesym:
	$(CXX) $(CXXFLAGS) writesym.cpp -o $(BIN_DIR)/writesym $(AR_OUT)

findsym:
	$(CXX) $(CXXFLAGS) findsym.cpp -o $(BIN_DIR)/findsym $(AR_OUT)

callsyscall:
	$(CC) $(CFLAGS) -O2 call_syscall.c -o $(BIN_DIR)/call_syscall

clean:
	rm -rf $(BIN_DIR)/findsym $(BIN_DIR)/readsym \
	$(BIN_DIR)/writesym $(BIN_DIR)/call_syscall \
	$(BIN_DIR)/unload $(BIN_DIR)/load
