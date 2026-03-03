#define PROGRAM		"telnetfp"
#define VERSION		"0.1.2"
#define AUTHOR		"palmers / teso"
#define DEFAULT_DB	"fps"
#define LINE_LENGTH	126


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>
#include <base_net.cpp>
#include <fingerdb.cpp>
