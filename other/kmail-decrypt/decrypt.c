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
/* Kmail POP3-passwd-'decryptor'. Just in case you forgot it.
 * Oh well, this is a very lame 'decryption' tool, just hacked down
 * in half an hour. 
 */
#include <stdio.h>
#include <errno.h>

const char *KMAILRC = "/root/.kde/share/config/kmailrc";
const int MAXENTRYS = 1000;

char *decrypt(char *s)
{
   	unsigned int d;
        static char result[1000];
        int i = 0;
        
        memset(result, 0, 1000);
        for (i = 0; i < strlen(s); i++) {
           	d = s[i] - ' ';
                d = 255 - d - ' ';
                result[i] = (char)(d + ' ');
        }
        return result;
}


int parse(FILE *f) {
        char buf[1000], user[1000], 
             host[1000], buf2[1000], *p;
        int complete = 0, entrys = 0;
        
        /* init a bit */
        memset(buf, 0, 1000);
        memset(user, 0, 100);
        memset(host, 0, 100);
        memset(buf2, 0, 1000);

        
        while (complete < 3 && entrys < MAXENTRYS) {
           	fgets(buf, 1000, f);
                
                /* if password found */
                if (sscanf(buf, "passwd=%s\n", buf2) <= 0) {
                   	memset(buf2, 0, 1000);
                } else {
                   	p = decrypt(buf2);
                        complete++;
                }
                
                /* if login found */
                if (sscanf(buf, "login=%s\n", buf2) <= 0) {
                   	memset(buf2, 0, 1000);
                } else {
                   	strncpy(user, buf2, 1000);
                        complete++;
                }
                        
                /* if host found */
                if (sscanf(buf, "host=%s\n", buf2) <= 0) {
                   	memset(buf2, 0, 1000);
                } else {
                   	strncpy(host, buf2, 1000);
                   	complete++;
                }
                entrys++;
                memset(buf2, 0, 1000);
                memset(buf, 0, 1000);
        }
        if (entrys < MAXENTRYS) {
           	printf("********\n"
                       "host: %s\n"
                       "user: %s\n"
                       "pwd: %s\n\n", host, user, p);
                return 1;
        } else
           	printf("No more complete entrys found (%d) :-(\n", complete);         
        return 0;
}



int main(int argc, char **argv)
{
        FILE *f;        

        if (argc > 1) {
           	KMAILRC = argv[1];
        }
        
        if ((f = fopen(KMAILRC, "r")) == NULL) {
           	perror("fopen");
                exit(errno);
        }
                
        while (parse(f));
        
        fclose(f);
        return 0;
}

