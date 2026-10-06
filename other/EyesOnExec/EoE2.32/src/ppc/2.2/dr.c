/*
 * Copyright (C) 1999/2000 Sebastian Krahmer.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastian Krahmer.
 * 4. The name Sebastian Krahmer may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*** Sample for EoE device. (C) 1999/2000 S. Krahmer
 ***/

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include "eoe.h"

int f = 0;

void handler(int s)
{
	printf("So never mind the darkness we still can find a way\n"
	       "'cause nothing lasts forever even cold november rain.\n"
	       " (guns n' roses)\n");
        exit(0);
}

int main()
{
   	int fd = 0;
        char buf[500] = {0};
	int euid = 0;    
	
        signal(SIGINT, handler);
        if ((fd = open("/dev/exec", O_RDWR)) < 0) {
           	perror("open");
                exit(errno);
        }
	if (ioctl(fd, EOE_SETALL) < 0) {
		perror("ioctl");
		exit(errno);
	}
        while (1) {
		bzero(buf, 500);
		read(fd, buf, 100); 
		printf("-> %s <-\n", buf);
        }
        close(fd);
        return 0;
}
